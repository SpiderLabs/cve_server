require 'spec_helper'
require 'cve_server/nvd/cvss'

module CvssSpec
  module_function

  def cvss
    [
      {
        cvss: {
          score: '7.5',
          access_vector: 'NETWORK',
          access_complexity: 'LOW',
          authentication: 'NONE',
          confidentiality_impact: 'PARTIAL',
          integrity_impact: 'PARTIAL',
          availability_impact: 'PARTIAL',
          source: 'http://nvd.nist.gov',
          generated_on_datetime: '2014-02-02T20:10:48.000-05:00'
        },
        expected_vector: 'AV:N/AC:L/Au:N/C:P/I:P/A:P'
      },
      {
        cvss: {
          score: '4.3',
          access_vector: 'NETWORK',
          access_complexity: 'MEDIUM',
          authentication: 'NONE',
          confidentiality_impact: 'NONE',
          integrity_impact: 'NONE',
          availability_impact: 'PARTIAL',
          source: 'http://nvd.nist.gov',
          generated_on_datetime: '2015-06-11T12:19:19.957-04:00',
        },
        expected_vector: 'AV:N/AC:M/Au:N/C:N/I:N/A:P'
      },
      {
        cvss: {
          'score': '4.0',
          'access_vector': 'NETWORK',
          'access_complexity': 'LOW',
          'authentication': 'SINGLE_INSTANCE',
          'confidentiality_impact': 'PARTIAL',
          'integrity_impact': 'NONE',
          'availability_impact': 'NONE',
          'source': 'http://nvd.nist.gov',
          'generated_on_datetime': '2015-02-09T13:50:39.923-05:00'
        },
        expected_vector: 'AV:N/AC:L/Au:S/C:P/I:N/A:N'
      },
      {
        cvss: {
          'score': '4.3',
          'access_vector': 'NETWORK',
          'access_complexity': 'MEDIUM',
          'authentication': 'NONE',
          'confidentiality_impact': 'NONE',
          'integrity_impact': 'PARTIAL',
          'availability_impact': 'NONE',
          'source': 'http://nvd.nist.gov',
          'generated_on_datetime': '2012-01-27T09:55:00.000-05:00',
        },
        expected_vector: 'AV:N/AC:M/Au:N/C:N/I:P/A:N'
      },
      {
        cvss: {
          'score': '7.6',
          'access_vector': 'NETWORK',
          'access_complexity': 'HIGH',
          'authentication': 'NONE',
          'confidentiality_impact': 'COMPLETE',
          'integrity_impact': 'COMPLETE',
          'availability_impact': 'COMPLETE',
          'source': 'http://nvd.nist.gov',
          'generated_on_datetime': '2011-03-03T16:58:00.000-05:00'
        },
        expected_vector: 'AV:N/AC:H/Au:N/C:C/I:C/A:C'
      },
    ]
  end

  def invalid_cvss
    [
      {
        cvss: {
          'score': '11.3',
          'access_vector': 'NETWORK',
          'access_complexity': 'MEDIUM',
          'confidentiality_impact': 'NONE',
          'integrity_impact': 'PARTIAL',
          'availability_impact': 'NONE',
          'source': 'http://nvd.nist.gov',
          'generated_on_datetime': '2012-01-27T09:55:00.000-05:00',
        }
      },
      {
        cvss: {
          'score': '-7.6',
          'access_vector': 'NETWORK',
          'access_complexity': 'HIGH',
          'authentication': 'NONE',
          'availability_impact': 'COMPLETE',
          'source': 'http://nvd.nist.gov',
          'generated_on_datetime': '2011-03-03T16:58:00.000-05:00'
        }
      },
    ]
  end
end

describe 'CVEServer::NVD::Cvss' do
  before :all do
    @klass = CVEServer::NVD::Cvss
  end

  CvssSpec.cvss.each do |entry|
    context 'Passes valid cvss entry' do
      before :each do
        @cvss = @klass.new(entry[:cvss])
      end

      it "should have a valid vector" do
        expect(@cvss.send('valid_vector?')).to be true
      end

      it "should have a valid score" do
        expect(@cvss.send('valid_score?')).to be true
      end

      it "should have valid metrics" do
        expect(@cvss.send('valid_metrics?')).to be true
      end

      it "should expect the vector #{entry[:expected_vector]}" do
        expect(@cvss.send('raw_vector')).to be == entry[:expected_vector]
      end

      it "should expect a hash including the vector" do
        h = entry[:cvss].merge!(vector: entry[:expected_vector])
        expect(@cvss.to_hash).to be == h
      end
    end
  end

  CvssSpec.invalid_cvss.each do |entry|
    context 'Should not validate invalid cvss entry ' do
      before :each do
        @cvss = @klass.new(entry[:cvss])
      end

      it "should not have a valid vector" do
        expect(@cvss.send('valid_vector?')).to be false
      end

      it "should not have a valid score" do
        expect(@cvss.send('valid_score?')).to be false
      end

      it "should not have valid metrics" do
        expect(@cvss.send('valid_metrics?')).to be false
      end

      it "should expect the original hash" do
        expect(@cvss.to_hash).to be == entry[:cvss]
      end
    end
  end
end
