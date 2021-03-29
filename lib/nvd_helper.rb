#!/usr/bin/env ruby

module NVDHelper

  def valid_json?(json)
    JSON.parse(json)
  rescue JSON::ParserError => e
    return false
  end

  def dest_path(page)
    filename = "#{Time.now.strftime('%Y-%m-%dT%H-%M-%S_')}#{page}.json.gz"
    File.join(CVEServer::Boot.config.raw_data_path, filename)
  end

  def last_data_timestamp
    latest_file = Dir.glob(CVEServer::Boot.config.raw_data_path+"/*").max_by {|f| File.mtime(f)}
    if latest_file.nil?
      print "No local files available\n"
      return nil
    end
    print "Newest local file is #{latest_file}\n"
    puts "Uncompressing #{latest_file}"
    file = Zlib::GzipReader.open(latest_file).read
    unless parsed = valid_json?(file)
      print "Newest local file fails JSON parsing, continuing as if there are no files."
      return nil
    end
    print "The CVE_data_timestamp is #{parsed["CVE_data_timestamp"]}\n"
    return "#{Time.parse(parsed["CVE_data_timestamp"]).strftime("%FT%T:%L")}"+"%20UTC"
  end

  def download(url)
    uri = URI.parse(url)
    use_ssl = uri.scheme == 'https'
    Net::HTTP.start(uri.host, uri.port, use_ssl: use_ssl) do |http|
      begin
        http.request_get(uri) do |response|
          case response
          when Net::HTTPSuccess then
            return response.body
          when Net::HTTPRedirection then
            location = response['location']
            fail "redirected to #{location}"
          else
            fail "Unable to download #{url}"
          end
        end
      rescue
        print "Retrying ... #{uri}\n"
        sleep(15)
        retry
      end
    end
  end

  def download_pages(data_timestamp = nil)
    if data_timestamp.nil?
      nvd_url_mod = "?"
    else
      nvd_url_mod = "?modStartDate=#{data_timestamp}&includeMatchStringChange=true&"
    end

    nvd_url = "https://services.nvd.nist.gov/rest/json/cves/1.0"
    print "Starting download...\n"
    nvd_response = download(nvd_url+nvd_url_mod+"resultsPerPage=1")

    unless nvd_parsed = valid_json?(nvd_response)
      abort "Unable to parse downloaded page!"
    end

    if nvd_parsed["totalResults"] == 0
      print "No new CVE to download!\n"
      exit
    end

    totalResults = nvd_parsed["totalResults"]
    resultPages = totalResults / 1000
    remainingResults = totalResults % 1000
    file_list = []

    print "Total CVE items to download #{totalResults}.\n"
    (0..resultPages).each do |page|
      if page*1000+999 >= totalResults
        print "Downloading CVE Items #{page*1000} to #{page*1000+remainingResults}\n"
      else
        print "Downloading CVE Items #{page*1000} to #{page*1000+999}\n"
      end

      # NIST firewall rules in place to prevent denial of service attacks
      # it is recommended that your application sleeps for several seconds between requests
      sleep(15)
      
      nvd_response = download(nvd_url+nvd_url_mod+"startIndex=#{page*1000}&resultsPerPage=1000")
      if nvd_json = valid_json?(nvd_response)
        if nvd_url_mod == "?"
          local_json_file = dest_path((page*1000).to_s + "_seed")
        else
          local_json_file = dest_path((page*1000).to_s + "_update")
        end  
        #local_json_file = dest_path(page*1000)
        print "Writing file #{local_json_file}...\n"
        #File.write(local_json_file, JSON.dump(nvd_json["result"]))
        Zlib::GzipWriter.open(local_json_file) do |gz|
          gz.write JSON.dump(nvd_json["result"])
        end
        file_list << local_json_file
      end
    end
    file_list
  end
end

