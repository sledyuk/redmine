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

class Redmine::ApiTest::PersonalAccessTokenTest < Redmine::ApiTest::Base
  VALID_PLAINTEXT = "rmpat_1234567890abcdef1234567890abcdef12345678"
  EXPIRED_PLAINTEXT = "rmpat_expired67890abcdef1234567890abcdef123456"

  test "should authenticate with a personal access token in the X-Redmine-API-Key header" do
    get '/users/current.json', :headers => {'X-Redmine-API-Key' => VALID_PLAINTEXT}
    assert_response :success
    assert_equal users(:users_002).login, ActiveSupport::JSON.decode(response.body)['user']['login']
  end

  test "should authenticate with a personal access token as the key parameter" do
    get "/users/current.json?key=#{VALID_PLAINTEXT}"
    assert_response :success
    assert_equal users(:users_002).login, ActiveSupport::JSON.decode(response.body)['user']['login']
  end

  test "should authenticate with a personal access token as HTTP Basic username" do
    get '/users/current.json', :headers => credentials(VALID_PLAINTEXT, 'X')
    assert_response :success
    assert_equal users(:users_002).login, ActiveSupport::JSON.decode(response.body)['user']['login']
  end

  test "should deny an expired personal access token" do
    get '/users/current.json', :headers => {'X-Redmine-API-Key' => EXPIRED_PLAINTEXT}
    assert_response :unauthorized
  end

  test "should deny a revoked personal access token" do
    PersonalAccessToken.find(1).destroy
    get '/users/current.json', :headers => {'X-Redmine-API-Key' => VALID_PLAINTEXT}
    assert_response :unauthorized
  end

  test "should still authenticate with a legacy api key" do
    user = users(:users_002)
    token = Token.create!(:user => user, :action => 'api')
    get '/users/current.json', :headers => {'X-Redmine-API-Key' => token.value}
    assert_response :success
    assert_equal user.login, ActiveSupport::JSON.decode(response.body)['user']['login']
  end

  test "should deny personal access tokens when the REST API is disabled" do
    with_settings :rest_api_enabled => '0', :login_required => '1' do
      get '/users/current.json', :headers => {'X-Redmine-API-Key' => VALID_PLAINTEXT}
      assert_response :forbidden
    end
  end
end
