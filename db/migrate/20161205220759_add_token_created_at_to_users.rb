class AddTokenCreatedAtToUsers < ActiveRecord::Migration[5.0]
  def change
    add_column :users, :token_created_at, :datetime
    remove_index :users, :token
    add_index :users, [:token, :token_created_at]
  end
end
