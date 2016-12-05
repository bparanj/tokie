class HackerSpotsController < ApiController
  before_action :require_login
  
  # This is protected by API token
  def index
    render json: { spots: 'List of places to work in coffee shops'}
  end
end

