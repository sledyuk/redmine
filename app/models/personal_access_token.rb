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

class PersonalAccessToken < ApplicationRecord
  include Redmine::SafeAttributes

  belongs_to :user

  # Plaintext token values are "rmpat_" followed by 40 hex characters.
  # Only the SHA256 digest of the full value is persisted.
  TOKEN_PREFIX = 'rmpat_'

  # Delay between two updates of last_used_on for the same token
  LAST_USED_THROTTLE = 1.hour

  validates_presence_of :name, :expires_on
  validates_length_of :name, maximum: 255
  validates_uniqueness_of :name, scope: :user_id, case_sensitive: false
  validate :validate_expires_on

  before_create :generate_value

  safe_attributes 'name', 'expires_on'

  # The plaintext value, only available on the instance that created it
  attr_reader :plaintext_value

  # Creates a token for +user+ and returns [record, plaintext value].
  # The plaintext value cannot be retrieved afterwards.
  def self.generate!(user:, name:, expires_on:)
    token = create!(user: user, name: name, expires_on: expires_on)
    [token, token.plaintext_value]
  end

  def self.hash_value(plaintext)
    Digest::SHA256.hexdigest(plaintext)
  end

  # Returns the active user owning the given plaintext token value,
  # or nil when the token is unknown, expired or its user is not active.
  def self.find_active_user(plaintext)
    return nil if plaintext.blank?

    token = find_by(token_digest: hash_value(plaintext.to_s))
    return nil unless token
    return nil unless ActiveSupport::SecurityUtils.secure_compare(token.token_digest, hash_value(plaintext.to_s))
    return nil if token.expired?
    return nil unless token.user&.active?

    token.touch_last_used_on
    token.user
  end

  def expired?
    expires_on < Date.today
  end

  def touch_last_used_on
    if last_used_on.nil? || last_used_on < LAST_USED_THROTTLE.ago
      update_column(:last_used_on, Time.now)
    end
  end

  private

  def generate_value
    @plaintext_value = TOKEN_PREFIX + Redmine::Utils.random_hex(20)
    self.token_digest = self.class.hash_value(@plaintext_value)
  end

  def validate_expires_on
    return if expires_on.blank?

    if expires_on < Date.today
      errors.add(:expires_on, :invalid)
    elsif Setting.personal_access_token_max_lifetime.to_i > 0 &&
          expires_on > Setting.personal_access_token_max_lifetime.to_i.days.from_now.to_date
      errors.add(:expires_on, :invalid)
    end
  end
end
