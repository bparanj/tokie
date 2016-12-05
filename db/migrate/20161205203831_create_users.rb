class CreateUsers < ActiveRecord::Migration[5.0]
  def change
    create_table :users do |t|
      t.string :name
      t.string :token
      t.string :email
      t.string :password_digest

      t.timestamps
    end
    add_index :users, :token
  end
end
