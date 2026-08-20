# frozen_string_literal: true

# Redmine - project management software
# Copyright (C) 2006-  Jean-Philippe Lang
#
# This program is free software; you can redistribute it and/or
# modify it under the terms of the GNU General Public License
# as published by the Free Software Foundation; either version 2
# of the License, or (at your option) any later version.
#
# This program is distributed in the hope that it will be useful,
# but WITHOUT ANY WARRANTY; without even the implied warranty of
# MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
# GNU General Public License for more details.
#
# You should have received a copy of the GNU General Public License
# along with this program; if not, write to the Free Software
# Foundation, Inc., 51 Franklin Street, Fifth Floor, Boston, MA  02110-1301, USA.

require_relative '../../test_helper'

class Redmine::ApiTest::ApiAuditTest < Redmine::ApiTest::Base
  VALID_PLAINTEXT = "rmpat_1234567890abcdef1234567890abcdef12345678"

  def setup
    super
    @io = StringIO.new
    @previous_logger = Redmine::ApiAudit.logger
    Redmine::ApiAudit.logger = Logger.new(@io)
    Redmine::ApiAudit.logger.formatter = proc {|_severity, _time, _progname, msg| "#{msg}\n"}
  end

  def teardown
    super
    Redmine::ApiAudit.logger = @previous_logger
  end

  test "should log a personal access token request when enabled" do
    with_settings :api_audit_logging_enabled => '1' do
      get '/users/current.json', :headers => {'X-Redmine-API-Key' => VALID_PLAINTEXT}
    end
    assert_response :success

    entry = last_entry
    assert_equal 'pat:1', entry['credential']
    assert_equal 2, entry['user_id']
    assert_equal 'jsmith', entry['user']
    assert_equal 'GET', entry['method']
    assert_equal '/users/current.json', entry['path']
    assert_equal 200, entry['status']
    assert entry['at'].present?
    assert entry['ip'].present?
  end

  test "should log a legacy api key request when enabled" do
    token = Token.create!(:user => users(:users_002), :action => 'api')
    with_settings :api_audit_logging_enabled => '1' do
      get '/users/current.json', :headers => {'X-Redmine-API-Key' => token.value}
    end
    assert_response :success
    assert_equal 'api_key', last_entry['credential']
  end

  test "should not log anything when disabled" do
    with_settings :api_audit_logging_enabled => '0' do
      get '/users/current.json', :headers => {'X-Redmine-API-Key' => VALID_PLAINTEXT}
    end
    assert_response :success
    assert_equal '', @io.string
  end

  test "should never log the token value" do
    with_settings :api_audit_logging_enabled => '1' do
      get "/users/current.json?key=#{VALID_PLAINTEXT}"
    end
    assert_response :success
    assert_not_includes @io.string, VALID_PLAINTEXT
    assert_equal '/users/current.json', last_entry['path']
  end

  private

  def last_entry
    ActiveSupport::JSON.decode(@io.string.lines.last)
  end
end
