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

class PersonalAccessTokenTest < ActiveSupport::TestCase
  VALID_PLAINTEXT = "rmpat_1234567890abcdef1234567890abcdef12345678"
  EXPIRED_PLAINTEXT = "rmpat_expired67890abcdef1234567890abcdef123456"
  LOCKED_USER_PLAINTEXT = "rmpat_locked7890abcdef1234567890abcdef12345678"

  test "generate! should return the record and a prefixed plaintext value" do
    token, plaintext = PersonalAccessToken.generate!(
      user: users(:users_002), name: 'Deploy script', expires_on: 30.days.from_now.to_date
    )
    assert token.persisted?
    assert plaintext.start_with?('rmpat_')
    assert_equal 46, plaintext.length
  end

  test "generate! should store only the SHA256 digest of the value" do
    token, plaintext = PersonalAccessToken.generate!(
      user: users(:users_002), name: 'Deploy script', expires_on: 30.days.from_now.to_date
    )
    assert_equal Digest::SHA256.hexdigest(plaintext), token.token_digest
    assert_not token.attributes.value?(plaintext)
  end

  test "should require a name" do
    token = PersonalAccessToken.new(
      user: users(:users_002), name: '', expires_on: 30.days.from_now.to_date
    )
    assert_not token.valid?
    assert token.errors[:name].present?
  end

  test "should require a unique name per user" do
    duplicate = PersonalAccessToken.new(
      user: users(:users_002), name: 'CI pipeline', expires_on: 30.days.from_now.to_date
    )
    assert_not duplicate.valid?
    assert duplicate.errors[:name].present?

    other_user = PersonalAccessToken.new(
      user: users(:users_003), name: 'CI pipeline', expires_on: 30.days.from_now.to_date
    )
    assert other_user.valid?
  end

  test "should require an expiration date" do
    token = PersonalAccessToken.new(user: users(:users_002), name: 'No expiry')
    assert_not token.valid?
    assert token.errors[:expires_on].present?
  end

  test "should reject an expiration date in the past" do
    token = PersonalAccessToken.new(
      user: users(:users_002), name: 'Past expiry', expires_on: Date.yesterday
    )
    assert_not token.valid?
    assert token.errors[:expires_on].present?
  end

  test "should enforce the admin max lifetime setting" do
    with_settings :personal_access_token_max_lifetime => '30' do
      too_far = PersonalAccessToken.new(
        user: users(:users_002), name: 'Too far', expires_on: 31.days.from_now.to_date
      )
      assert_not too_far.valid?
      assert too_far.errors[:expires_on].present?

      at_limit = PersonalAccessToken.new(
        user: users(:users_002), name: 'At limit', expires_on: 30.days.from_now.to_date
      )
      assert at_limit.valid?
    end
  end

  test "should not limit lifetime when the setting is zero" do
    with_settings :personal_access_token_max_lifetime => '0' do
      token = PersonalAccessToken.new(
        user: users(:users_002), name: 'Far future', expires_on: 10.years.from_now.to_date
      )
      assert token.valid?
    end
  end

  test "expired? should be true only after the expiration date" do
    assert personal_access_tokens(:personal_access_tokens_002).expired?
    assert_not personal_access_tokens(:personal_access_tokens_001).expired?
  end

  test "find_active_user should return the owner for a valid token" do
    assert_equal users(:users_002), PersonalAccessToken.find_active_user(VALID_PLAINTEXT)
  end

  test "find_active_user should return nil for an expired token" do
    assert_nil PersonalAccessToken.find_active_user(EXPIRED_PLAINTEXT)
  end

  test "find_active_user should return nil for a locked user" do
    assert_nil PersonalAccessToken.find_active_user(LOCKED_USER_PLAINTEXT)
  end

  test "find_active_user should return nil for unknown or blank keys" do
    assert_nil PersonalAccessToken.find_active_user('rmpat_unknown')
    assert_nil PersonalAccessToken.find_active_user('')
    assert_nil PersonalAccessToken.find_active_user(nil)
  end

  test "find_active_user should record last_used_on" do
    token = personal_access_tokens(:personal_access_tokens_001)
    assert_nil token.last_used_on
    PersonalAccessToken.find_active_user(VALID_PLAINTEXT)
    assert_not_nil token.reload.last_used_on
  end

  test "import_legacy_api_tokens! should convert legacy api keys to hashed tokens" do
    user = users(:users_003)
    legacy = Token.create!(:user => user, :action => 'api')
    legacy_value = legacy.value

    assert_difference 'PersonalAccessToken.count', 1 do
      assert_difference 'Token.where(:action => "api").count', -1 do
        PersonalAccessToken.import_legacy_api_tokens!
      end
    end

    imported = PersonalAccessToken.order(:id => :desc).first
    assert_equal user, imported.user
    assert_equal Digest::SHA256.hexdigest(legacy_value), imported.token_digest
    assert_equal 365.days.from_now.to_date, imported.expires_on
    # The same key keeps authenticating after the import
    assert_equal user, PersonalAccessToken.find_active_user(legacy_value)
  end

  test "import_legacy_api_tokens! should be idempotent" do
    Token.create!(:user => users(:users_003), :action => 'api')
    PersonalAccessToken.import_legacy_api_tokens!
    assert_no_difference 'PersonalAccessToken.count' do
      PersonalAccessToken.import_legacy_api_tokens!
    end
  end

  test "import_legacy_api_tokens! should honor the max lifetime setting" do
    Token.create!(:user => users(:users_003), :action => 'api')
    with_settings :personal_access_token_max_lifetime => '30' do
      PersonalAccessToken.import_legacy_api_tokens!
    end
    assert_equal 30.days.from_now.to_date, PersonalAccessToken.order(:id => :desc).first.expires_on
  end

  test "find_active_user should throttle last_used_on updates" do
    token = personal_access_tokens(:personal_access_tokens_001)
    recent = 5.minutes.ago
    token.update_column(:last_used_on, recent)
    PersonalAccessToken.find_active_user(VALID_PLAINTEXT)
    assert_equal recent.to_i, token.reload.last_used_on.to_i

    stale = 2.hours.ago
    token.update_column(:last_used_on, stale)
    PersonalAccessToken.find_active_user(VALID_PLAINTEXT)
    assert_operator token.reload.last_used_on, :>, 1.minute.ago
  end
end
