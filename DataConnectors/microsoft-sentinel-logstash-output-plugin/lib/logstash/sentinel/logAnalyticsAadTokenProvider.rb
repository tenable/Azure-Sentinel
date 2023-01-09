# encoding: utf-8
require "logstash/sentinel/logstashLoganalyticsConfiguration"
require 'rest-client'
require 'json'
require 'openssl'
require 'base64'
require 'time'

module LogStash; module Outputs; class MicrosoftSentinelOutputInternal
class LogAnalyticsAadTokenProvider
  def initialize (logstashLoganalyticsConfiguration)
    set_proxy(logstashLoganalyticsConfiguration.proxy)
    scope = CGI.escape("https://monitor.azure.com//.default")
    @token_request_body = sprintf("client_id=%s&scope=%s&client_secret=%s&grant_type=client_credentials", logstashLoganalyticsConfiguration.client_app_Id, scope, logstashLoganalyticsConfiguration.client_app_secret)
    @token_request_uri = sprintf("https://login.microsoftonline.com/%s/oauth2/v2.0/token", logstashLoganalyticsConfiguration.tenant_id)
    @token_state = {
      :access_token => nil,
      :expiry_time => nil,
      :token_details_mutex => Mutex.new,
    }
    @logger = logstashLoganalyticsConfiguration.logger
  end # def initialize

  # Public methods
  public

  def get_aad_token_bearer()
    @token_state[:token_details_mutex].synchronize do
      if is_saved_token_need_refresh()
        refresh_saved_token()
      end
      return @token_state[:access_token]
    end
  end # def get_aad_token_bearer

  # Private  methods
  private
  
  def is_saved_token_need_refresh()
    return @token_state[:access_token].nil? || @token_state[:expiry_time].nil? || @token_state[:expiry_time] <= Time.now
  end # def is_saved_token_need_refresh

  def refresh_saved_token()
    @logger.info("aad token expired - refreshing token.")

    token_response = post_token_request()
    @token_state[:access_token] = token_response["access_token"]
    @token_state[:expiry_time] = get_token_expiry_time(token_response["expires_in"])
  end # def refresh_saved_token

  def get_token_expiry_time (expires_in_seconds)
    if (expires_in_seconds.nil? || expires_in_seconds <= 0)
      return Time.now + (60 * 60 * 24) # Refresh anyway in 24 hours
    else
      return Time.now + expires_in_seconds - 1; # Decrease by 1 second to be on the safe side
    end
  end # def get_token_expiry_time

  # Post the given json to Azure Loganalytics
  def post_token_request()
    # Create REST request header
    header = get_header()
    begin
        # Post REST request 
        response = RestClient.post(@token_request_uri, @token_request_body, header)        
        if (response.code == 200 || response.code == 201)
          return JSON.parse(response.body)
        else
          @logger.trace("Rest client response from ADD API ['#{response}']")
          raise ("Failed to get AAD token: http code " + response.code.to_s)
        end
    rescue RestClient::ExceptionWithResponse => ewr
        @logger.trace("Rest client response from ADD API ['#{ewr.response}']")
        raise ("Failed to get AAD token: http code " + ewr.response.code.to_s)
    end
  end # def post_token_request

  # Create a header
  def get_header()
    return {
      'Content-Type' => 'application/x-www-form-urlencoded',
    }
  end # def get_header

  # Setting proxy for the REST client.
  # This option is not used in the output plugin and will be used 
  #  
  def set_proxy(proxy='')
    RestClient.proxy = proxy.empty? ? ENV['http_proxy'] : proxy
  end # def set_proxy

end # end of class
end ;end ;end 