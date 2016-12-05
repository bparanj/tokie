# README


1
```
rails g model user name token email password_digest
```

```ruby
add_index :users, :token
```
2

```ruby
class User < ApplicationRecord
  has_secure_password
end
```

3. 

```ruby
gem 'bcrypt'
```

Run bundle install. This installs : bcrypt 3.1.11.

4
Seed the db.

```ruby
User.destroy_all
User.create(name: 'bugs', email: 'bugs@rubyplus.com', password: '123456')
User.create(name: 'daffy', email: 'daffy@rubyplus.com', password: '123456')
```

```
rails db:migrate
rails db:seed
```

5.
Implement signin. Return token for successful signin else return error json.

```
rails g controller api
```

```ruby
class ApiController < ActionController::Base
  def require_login
    authenticate_token || render_unauthorized("Access denied")
  end
      
  def current_user
    @current_user ||= authenticate_token
  end
  
  protected
  
  def render_unauthorized(message)
    errors = { errors: [ { detail: message } ] }
    render json: errors, status: :unauthorized
  end
  
  private
  
  def authenticate_token
    authenticate_with_http_token do |token, options|
      User.find_by(token: token)
    end
  end  
end
```

```ruby
class SessionsController < ApiController
  skip_before_action :require_login, only: [:create], raise: false

  def create
    if user = User.valid_login?(params[:email], params[:password])
      allow_token_to_be_used_only_once_for(user)
      send_auth_token_for_valid_login_of(user)
    else
      render_unauthorized("Error with your login or password")
    end
  end

  def destroy
    logout
    head :ok
  end

  private
  
  def send_auth_token_for_valid_login_of(user)
    render json: { token: user.token }
  end
  
  def allow_token_to_be_used_only_once_for(user)
    user.regenerate_token
  end
  
  def logout
    current_user.invalidate_token
  end
end
```

```ruby
class User < ApplicationRecord
  has_secure_password
  has_secure_token
  
  # This method is not available in has_secure_token
  def invalidate_token
    self.update_columns(token: nil)
  end
  
  def self.valid_login?(email, password)
    user = find_by(email: email)
    if user && user.authenticate(password)
      user
    end
  end
end
```

6.

```ruby
Rails.application.routes.draw do
  get 'hacker_spots/index'

  scope :format => true, :constraints => { :format => 'json' } do
    post   "/login"       => "sessions#create"
    delete "/logout"      => "sessions#destroy"
  end
end
```

7.

```ruby
class HackerSpotsController < ApiController
  before_action :require_login
  
  # This is protected by API token
  def index
    render json: { spots: 'List of places to work in coffee shops'}
  end
end
```

8.

Curl commands to test the API.

Initial Authorization
```
curl -X POST --data "email=bugs@rubyplus.com&password=123456" http://localhost:3010/login.json
```

Incorrect Login Credentials

```
curl -X POST --data "email=bugs@rubyplus.com&password=123" http://localhost:3010/login.json
```

Protected Calls

```
curl -H "Authorization: Token token=aQNeG5FtnrgU49eC42mShNjX" http://localhost:3010/hacker_spots/index.json
```
Sign out

```
curl -X DELETE -H "Authorization: Token token=aQNeG5FtnrgU49eC42mShNjX" http://localhost:3010/logout.json
```

9.
Mitigate Timing Attacks. In API controller.

```ruby
def authenticate_token
  authenticate_with_http_token do |token, options|
    # Compare the tokens in a time-constant manner, to mitigate timing attacks.
    if user = User.find_by(token: token)
      ActiveSupport::SecurityUtils.secure_compare(
                      ::Digest::SHA256.hexdigest(token),
                      ::Digest::SHA256.hexdigest(user.token))
      user
    end
  end
end  
```

10. Expiration.

```
$ rails g migration add_token_created_at_to_users token_created_at:datetime
```

Add compound index:

```ruby
class AddTokenCreatedAtToUsers < ActiveRecord::Migration[5.0]
  def change
    add_column :users, :token_created_at, :datetime
    remove_index :users, :token
    add_index :users, [:token, :token_created_at]
  end
end
```

```
rails db:migrate
```

11. Touch the attribute when we create and destroy tokens.

Api controller:

```ruby
def authenticate_token
  authenticate_with_http_token do |token, options|
    if user = User.with_unexpired_token(token, 2.days.ago)
      # Compare the tokens in a time-constant manner, to mitigate timing attacks.
      ActiveSupport::SecurityUtils.secure_compare(
                      ::Digest::SHA256.hexdigest(token),
                      ::Digest::SHA256.hexdigest(user.token))
      user
    end
  end
end  
```

User:

```ruby
class User < ApplicationRecord
  has_secure_password
  has_secure_token
    
  def self.valid_login?(email, password)
    user = find_by(email: email)
    if user && user.authenticate(password)
      user
    end
  end
  
  def allow_token_to_be_used_only_once
    regenerate_token
    touch(:token_created_at)
  end
  
  def logout
    invalidate_token
  end
  
  def with_unexpired_token(token, period)
    where(token: token).where('token_created_at >= ?', period).first
  end
  
  private
  
  # This method is not available in has_secure_token
  def invalidate_token
    update_columns(token: nil)
    touch(:token_created_at)
  end
end
```

Tip : Use -I switch in Curl to view the http response headers.

References
============

- [Mitigate Timing Attacks](http://api.rubyonrails.org/classes/ActionController/HttpAuthentication/Token.html 'Rails Token Authentication')
- [Token Based Authentication Rails](https://www.codeschool.com/blog/2014/02/03/token-based-authentication-rails/ 'Token Based Authentication Rails')
- [Rails 5 Security Utils](https://github.com/rails/rails/blob/92703a9ea5d8b96f30e0b706b801c9185ef14f0e/activesupport/lib/active_support/security_utils.rb 'Rails 5 Security Utils')
- [has_secure_token in Rails 5](http://api.rubyonrails.org/classes/ActiveRecord/SecureToken/ClassMethods.html 'has_secure_token in Rails 5')
- [has_secure_password in Rails 5](http://api.rubyonrails.org/classes/ActiveModel/SecurePassword/ClassMethods.html 'has_secure_password in Rails 5')
- [Rack Middleware for Blocking and Throttling](https://github.com/kickstarter/rack-attack 'Rack Middleware for Blocking and Throttling')