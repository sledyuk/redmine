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

require_relative '../test_helper'

class PersonalAccessTokensControllerTest < Redmine::ControllerTest
  def setup
    @request.session[:user_id] = 2
  end

  def test_index_should_list_only_own_tokens
    get :index
    assert_response :success
    assert_select 'table.list tbody' do
      assert_select 'tr', 2
      assert_select 'td', :text => 'CI pipeline'
      assert_select 'td', :text => 'Locked user token', :count => 0
    end
  end

  def test_index_should_require_login
    @request.session[:user_id] = nil
    get :index
    assert_response :redirect
  end

  def test_new_should_display_the_form
    get :new
    assert_response :success
    assert_select 'input[name=?]', 'personal_access_token[name]'
    assert_select 'input[name=?]', 'personal_access_token[expires_on]'
  end

  def test_new_should_display_scope_checkboxes
    get :new
    assert_response :success
    assert_select 'input[type=checkbox][name=?]', 'personal_access_token[scopes][]', :minimum => 10
    assert_select 'input[type=checkbox][name=?][value=admin]', 'personal_access_token[scopes][]'
  end

  def test_index_should_show_a_scopes_summary
    PersonalAccessToken.find(1).update_column(:scopes, 'view_issues add_issues')
    get :index
    assert_response :success
    assert_select 'tr#personal-access-token-1 td.scopes', :text => '2'
    assert_select 'tr#personal-access-token-2 td.scopes', :text => 'Full access'
  end

  def test_create_with_scopes_should_store_them
    post :create, :params => {
      :personal_access_token => {
        :name => 'Scoped token',
        :expires_on => 30.days.from_now.to_date.to_s,
        :scopes => ['', 'view_issues']
      }
    }
    assert_redirected_to '/my/personal_access_tokens'
    assert_includes PersonalAccessToken.order(:id => :desc).first.scope_list, :view_issues
  end

  def test_new_should_clamp_the_default_expiration_to_the_max_lifetime
    with_settings :personal_access_token_max_lifetime => '7' do
      get :new
      assert_response :success
      assert_select 'input[name=?][value=?]', 'personal_access_token[expires_on]',
                    7.days.from_now.to_date.to_s
    end
  end

  def test_create_should_add_a_token_and_show_its_value_once
    assert_difference 'PersonalAccessToken.count', 1 do
      post :create, :params => {
        :personal_access_token => {
          :name => 'Deploy script',
          :expires_on => 30.days.from_now.to_date.to_s
        }
      }
    end
    assert_redirected_to '/my/personal_access_tokens'
    token = PersonalAccessToken.order(:id => :desc).first
    assert_equal users(:users_002), token.user

    follow_redirect_and_assert_token_displayed
  end

  def test_create_with_invalid_params_should_redisplay_the_form
    assert_no_difference 'PersonalAccessToken.count' do
      post :create, :params => {
        :personal_access_token => {:name => '', :expires_on => 30.days.from_now.to_date.to_s}
      }
    end
    assert_response :success
    assert_select_error /Name/
  end

  def test_destroy_should_remove_own_token
    assert_difference 'PersonalAccessToken.count', -1 do
      delete :destroy, :params => {:id => 1}
    end
    assert_redirected_to '/my/personal_access_tokens'
  end

  def test_destroy_should_not_remove_another_users_token
    assert_no_difference 'PersonalAccessToken.count' do
      delete :destroy, :params => {:id => 3}
    end
    assert_response :not_found
  end

  private

  def follow_redirect_and_assert_token_displayed
    # The plaintext value is passed through the flash and displayed once
    get :index
    assert_response :success
    assert_select 'pre.personal-access-token-value', :text => /\Armpat_[0-9a-f]{40}\z/
    # A second render must not display it again
    get :index
    assert_select 'pre.personal-access-token-value', :count => 0
  end
end
