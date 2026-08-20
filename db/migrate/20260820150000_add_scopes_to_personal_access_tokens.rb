class AddScopesToPersonalAccessTokens < ActiveRecord::Migration[7.2]
  def change
    add_column :personal_access_tokens, :scopes, :text
  end
end
