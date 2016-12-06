# README

The user can login by providing a valid email and password. In a real project, this will be sent over a SSL connection. In this article, we will use Curl command that sends the user credentials in plain text format. Create a user model that has token for token for Token based authentication and password_digest for storing login password field. The password_digest is required for has_secure_password functionality provided by Rails. 

```
rails g model user name token email password_digest
```

Add the index for the token field in the migration.

```ruby
add_index :users, :token
```

Declare has_secure_password in the user model.

```ruby
class User < ApplicationRecord
  has_secure_password
end
```

We need to install bcrypt gem to use the has_secure_password Rails builtin functionality for storing encrypted passwords in our database. It also provides `authenticate` method to check if the password provided by the user is correct. Add the gem to Gemfile.

```ruby
gem 'bcrypt'
```

Run bundle install. This will install bcrypt gem version 3.1.11. Create some sample records in seeds.rb. 

```ruby
User.destroy_all
User.create(name: 'bugs', email: 'bugs@rubyplus.com', password: '123456')
User.create(name: 'daffy', email: 'daffy@rubyplus.com', password: '123456')
```

Run the migration and populate the database.

```
rails db:migrate
rails db:seed
```

Login User

Let's implement login. When a user successfully logs in, we will return token otherwise we will return error in json format. This token will be used in subsequent calls to the protected API endpoints. When the user logs out, the token will become invalid and no further calls to the protected endpoints can use the same token. When a user logs in again, a new token will be generated. Let's create a controller that holds all the API related functionality.

```
rails g controller api
```

The code is as shown below:

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

The `authenticate_with_http_token` takes the token provided in the header of the http request and makes it available in the `token` block variable. We ignore the `options` block variable, since we don't need it. Create a sessions controller that inherits from the ApiController.

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

In Rails 5, we need to use the `raise: false` in `skip_before_action` filter to return boolean instead of raising an exception. The user model is as shown below.

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

The `invalidate_token` method is required to expire a user's token. It should have been part of the has_secure_token functionality. Unfortunately, we have to implement it. The `has_secure_token` by default expects `token` column in the users table. We can customize it by providing it as an argument to the `has_secure_token` method:

```ruby
has_secure_token :auth_token
```

We are using has_secure_token to use the Rails builtin xyz. Define the routes to handle the API protected endpoints and the login/logout functionality. We only allow the json format request by specifying the format in the constraints option.

```ruby
Rails.application.routes.draw do
  get 'hacker_spots/index'

  scope :format => true, :constraints => { :format => 'json' } do
    post   "/login"       => "sessions#create"
    delete "/logout"      => "sessions#destroy"
  end
end
```

THe protected endpoint is a simple implementation that returns a json structure.

```ruby
class HackerSpotsController < ApiController
  before_action :require_login
  
  # This is protected by API token
  def index
    render json: { spots: 'List of places to work in coffee shops'}
  end
end
```

The `before_action` filter enforces the login requirement. The `require_login` is implemented in the ApiController. Here is the list of Curl commands to test the API from a terminal.

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

To mitigate timing attacks, change the API controller as follows:

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

Expiration of Tokens

We can expire the tokens to time out the inactive login sessions and force the client to login again. Add a `token_created_at` field to users table.

```
$ rails g migration add_token_created_at_to_users token_created_at:datetime
```

Add compound index to the generated migration:

```ruby
class AddTokenCreatedAtToUsers < ActiveRecord::Migration[5.0]
  def change
    add_column :users, :token_created_at, :datetime
    remove_index :users, :token
    add_index :users, [:token, :token_created_at]
  end
end
```

Run the migration.

```
rails db:migrate
```

Touch the attribute when we create and destroy tokens. In Api controller, call the `with_unexpired_token` User class method:

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

In user model, implement `with_unexpired_token` method. The complete source code for user is as follows:

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

Tip: Use -I switch in Curl to view the http response headers.

References
============

- [Mitigate Timing Attacks](http://api.rubyonrails.org/classes/ActionController/HttpAuthentication/Token.html 'Rails Token Authentication')
- [Token Based Authentication Rails](https://www.codeschool.com/blog/2014/02/03/token-based-authentication-rails/ 'Token Based Authentication Rails')
- [Rails 5 Security Utils](https://github.com/rails/rails/blob/92703a9ea5d8b96f30e0b706b801c9185ef14f0e/activesupport/lib/active_support/security_utils.rb 'Rails 5 Security Utils')
- [has_secure_token in Rails 5](http://api.rubyonrails.org/classes/ActiveRecord/SecureToken/ClassMethods.html 'has_secure_token in Rails 5')
- [has_secure_password in Rails 5](http://api.rubyonrails.org/classes/ActiveModel/SecurePassword/ClassMethods.html 'has_secure_password in Rails 5')
- [Rack Middleware for Blocking and Throttling](https://github.com/kickstarter/rack-attack 'Rack Middleware for Blocking and Throttling')