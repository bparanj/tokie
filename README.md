# README


1

rails g model user name token email password_digest

    add_index :users, :token

2

class User < ApplicationRecord
  has_secure_password
end

3. 

gem 'bcrypt'

bundle

installs : bcrypt 3.1.11

4

Seed the db.

User.destroy_all
User.create(name: 'bugs', email: 'bugs@rubyplus.com', password: '123456')
User.create(name: 'daffy', email: 'daffy@rubyplus.com', password: '123456')

rails db:migrate
rails db:seed

5.

Implement signin. Return token for successful signin else return error json.

rails g controller api


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


6.

Rails.application.routes.draw do
  get 'hacker_spots/index'

  scope :format => true, :constraints => { :format => 'json' } do
    post   "/login"       => "sessions#create"
    delete "/logout"      => "sessions#destroy"
  end
end

7.

class HackerSpotsController < ApiController
  before_action :require_login
  
  # This is protected by API token
  def index
    render json: { spots: 'List of places to work in coffee shops'}
  end
end

8.
Curl commands to test the API.

curl -X POST --data "email=bugs@rubyplus.com&password=123456" http://localhost:3010/login.json
curl -X DELETE -H "Authorization: Token token=aQNeG5FtnrgU49eC42mShNjX" http://localhost:3010/logout.json
curl -H "Authorization: Token token=aQNeG5FtnrgU49eC42mShNjX" http://localhost:3010/hacker_spots/index.json


References
============

- [Mitigate Timing Attacks](http://api.rubyonrails.org/classes/ActionController/HttpAuthentication/Token.html 'Rails Token Authentication')
- [Token Based Authentication Rails](https://www.codeschool.com/blog/2014/02/03/token-based-authentication-rails/ 'Token Based Authentication Rails')


