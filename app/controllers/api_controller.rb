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
      # Compare the tokens in a time-constant manner, to mitigate timing attacks.
      if user = User.find_by(token: token)
        ActiveSupport::SecurityUtils.secure_compare(
                        ::Digest::SHA256.hexdigest(token),
                        ::Digest::SHA256.hexdigest(user.token))
        user
      end
    end
  end  
end
