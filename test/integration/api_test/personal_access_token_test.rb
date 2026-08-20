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

  test "scoped token of an admin should not grant admin-only endpoints" do
    _token, plaintext = PersonalAccessToken.generate!(
      user: User.find(1), name: 'Scoped admin token',
      expires_on: 30.days.from_now.to_date, scopes: 'view_issues'
    )
    get '/users.json', :headers => {'X-Redmine-API-Key' => plaintext}
    assert_response :forbidden
  end

  test "unscoped token of an admin should grant admin-only endpoints" do
    _token, plaintext = PersonalAccessToken.generate!(
      user: User.find(1), name: 'Unscoped admin token',
      expires_on: 30.days.from_now.to_date
    )
    get '/users.json', :headers => {'X-Redmine-API-Key' => plaintext}
    assert_response :success
  end

  test "scoped token should grant endpoints covered by its scopes" do
    _token, plaintext = PersonalAccessToken.generate!(
      user: users(:users_002), name: 'Issues token',
      expires_on: 30.days.from_now.to_date, scopes: 'view_issues'
    )
    get '/issues.json', :headers => {'X-Redmine-API-Key' => plaintext}
    assert_response :success
  end

  test "scoped token should deny endpoints outside its scopes" do
    _token, plaintext = PersonalAccessToken.generate!(
      user: users(:users_002), name: 'Issues only token',
      expires_on: 30.days.from_now.to_date, scopes: 'view_issues'
    )
    get '/time_entries.json', :headers => {'X-Redmine-API-Key' => plaintext}
    assert_response :forbidden
  end

  # Known limitation inherited from the OAuth scope mechanism (upstream
  # defect https://www.redmine.org/issues/44271): Issue#attributes_editable?
  # authorizes through the private Issue#user_tracker_permission?, which
  # selects roles directly and never calls User#allowed_to?, so the scope
  # intersection is bypassed for issue attribute mutations. A token scoped
  # to view_issues + add_issue_notes (a typical comment-bot token) can
  # therefore still edit issue attributes when the user's role allows it,
  # because add_issue_notes maps to issues#update and passes the controller
  # authorize. This test pins the current behavior and will start failing
  # once #44271 is fixed upstream - update it then.
  test "KNOWN LIMITATION (#44271): add_issue_notes scope does not prevent issue attribute edits" do
    _token, plaintext = PersonalAccessToken.generate!(
      user: users(:users_002), name: 'Notes-only token',
      expires_on: 30.days.from_now.to_date, scopes: 'view_issues add_issue_notes'
    )
    put '/issues/1.json',
        :params => {:issue => {:subject => 'Changed through a notes-only token'}},
        :headers => {'X-Redmine-API-Key' => plaintext}
    assert_response :no_content
    assert_equal 'Changed through a notes-only token', Issue.find(1).subject
  end

  test "should deny personal access tokens when the REST API is disabled" do
    with_settings :rest_api_enabled => '0', :login_required => '1' do
      get '/users/current.json', :headers => {'X-Redmine-API-Key' => VALID_PLAINTEXT}
      assert_response :forbidden
    end
  end
end
