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

module Redmine
  # Structured audit log of authenticated REST API requests, one JSON
  # line per request, written to log/api_audit.log by default
  module ApiAudit
    mattr_accessor :logger

    def self.log(payload)
      self.logger ||= default_logger
      logger.info(payload.to_json)
    end

    def self.default_logger
      logger = Logger.new(Rails.root.join('log', 'api_audit.log'), 'weekly')
      logger.formatter = proc {|_severity, _time, _progname, msg| "#{msg}\n"}
      logger
    end
  end
end
