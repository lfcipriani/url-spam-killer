require "resolv"
require "uri"

require "spam_killer/url_shorteners"
require "spam_killer/whitelist"
require "spam_killer/tlds"

module SpamKiller
  class Helper
    
    class << self
      
      def url_is_spam?(target)
        begin
          host = URI.parse(target).host
          return true if SpamKiller::Helper.is_url_shortener?(host)
          unless SpamKiller::Helper.is_whitelisted?(host)
            return SpamKiller::Helper.is_blacklisted?(host)
          else
            return false
          end
        rescue Exception => e
          return true
        end
      end
      
      def dns
        @dns ||= Resolv::DNS.new
      end
    
      # lista de encurtadores
      def is_url_shortener?(url_host)
        SpamKiller::URL_SHORTENERS.include?(url_host)
      end
    
      # whitelist
      def is_whitelisted?(url_host)
        result = SpamKiller::WHITELIST.select {|v| url_host =~ /#{v}$/}
        return result.size > 0
      end
    
      # serviços
      def is_blacklisted?(url_host)
        result = []
        result << check_surbl(url_host)
        result << check_spamhaus(url_host)
        result.include?(:blocked)
      end
  
      def is_ip_address?(host)
        !(host =~ /(?:(?:25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)\.){3}(?:25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)/).nil?
      end
  
      def check_surbl(host)        
        if is_ip_address?(host)
           host = host.split(".").reverse.join(".")
        else
          tld = SpamKiller::TLDS.select {|v| host =~ /#{v}$/}
          tld_size = tld.size > 0 ? tld.last.split(".").size : 1
          host = host.split(".")[-1-(tld_size)..-1].join(".")
        end
        address = dns_resolv("#{host}.multi.surbl.org")
        if address.nil?
          return :ok
        elsif address == :error
          return :error
        else
          return :blocked
        end
      end
  
      def check_spamhaus(host)      
        unless is_ip_address?(host)
          address = dns_resolv("#{host}.dbl.spamhaus.org")
          if address.nil?
            return :ok
          elsif address == :error
            return :error
          elsif address == "127.0.1.255"
            return :ip_blocked
          else
            return :blocked
          end
        else
          return :forbiden
        end
      end
  
      def dns_resolv(name)
        begin
          result = dns.getresources(name, Resolv::DNS::Resource::IN::A)
          (result.size > 0 ? result.first.address.to_s : nil)
        rescue Resolv::ResolvError => e
          return :error
        end
      end
      
    end
    
  end
end