# see http://www.emilsoman.com/blog/2013/05/18/building-a-tested/
module DeviseTokenAuth
  class SessionsController < DeviseTokenAuth::ApplicationController
    before_filter :set_user_by_token, :only => [:destroy]

    swagger_controller :sessions, "Login and Logout"

    swagger_api :create do
      summary "Login"
      param :form, :username, :string, :required, "Username or email"
      param :form, :password, :password, :required, "Password"
      response :unauthorized
      response :not_found
      response :ok
    end

    def create
      # Check
      #field = (resource_params.keys.map(&:to_sym) & resource_class.authentication_keys).first

      @resource = nil
      # if field
      #   q_value = resource_params[field]

      #   if resource_class.case_insensitive_keys.include?(field)
      #     q_value.downcase!
      #   end

      #   q = "#{field.to_s} = ? AND provider='email'"

      #   if ActiveRecord::Base.connection.adapter_name.downcase.starts_with? 'mysql'
      #     q = "BINARY " + q
      #   end

      #   @resource = resource_class.where(q, q_value).first
      # end

      subdomain = request.headers['subdomain']
      organization = Organization.where(subdomain: subdomain).first if subdomain

      if organization
        q_value = resource_params[:username]

        q = "username = ? AND provider='email' AND organization_id = ?"

        if ActiveRecord::Base.connection.adapter_name.downcase.starts_with? 'mysql'
          q = "BINARY " + q
        end

        @resource = resource_class.where(q, q_value, organization.id).first

        if !@resource
          q = "email = ? AND provider='email' AND organization_id = ?"

          if ActiveRecord::Base.connection.adapter_name.downcase.starts_with? 'mysql'
            q = "BINARY " + q
          end

          @resource = resource_class.where(q, q_value, organization.id).first
        end

        if @resource and valid_params?(:username, q_value) and @resource.valid_password?(resource_params[:password]) and @resource.confirmed?
          if organization.status == "trial" && organization.trial_expiration_date > Time.zone.now && @resource.admin?
            render json: {
              success: false,
              errors: ["Your organization's trial period has expired. Please contact your admin."]
            }, status: 401
          elsif @resource.disabled
            render json: {
              success: false,
              errors: ["Your account has been disabled. Please contact your admin."]
            }, status: 401
          else
            # create client id
            @client_id = SecureRandom.urlsafe_base64(nil, false)
            @token     = SecureRandom.urlsafe_base64(nil, false)

            @resource.tokens[@client_id] = {
              token: BCrypt::Password.create(@token),
              expiry: (Time.now + DeviseTokenAuth.token_lifespan).to_i
            }
            @resource.save

            sign_in(:user, @resource, store: false, bypass: false)

            render json: {
              data: @resource.token_validation_response
            }
          end

        elsif @resource and not @resource.confirmed?
          render json: {
            success: false,
            errors: [
              "A confirmation email was sent to your account at #{@resource.email}. "+
              "You must follow the instructions in the email before your account "+
              "can be activated"
            ]
          }, status: 401

        elsif !@resource
          render json: {
            errors: ["This username or email does not exist. Please try again."]
          }, status: 401
        else
          render json: {
            errors: ["Sorry, you entered an incorrect email address or password."]
          }, status: 401
        end
      else
        render json: {
            errors: ["There is no organization with this subdomain"]
          }, status: 401
      end
    end

    swagger_api :destroy do
      summary "Logout"
      response :unauthorized
      response :not_found
      response :ok
    end

    def destroy
      # remove auth instance variables so that after_filter does not run
      user = remove_instance_variable(:@resource) if @resource
      client_id = remove_instance_variable(:@client_id) if @client_id
      remove_instance_variable(:@token) if @token

      if user and client_id and user.tokens[client_id]
        user.tokens.delete(client_id)
        user.save!

        render json: {
          success:true
        }, status: 200

      else
        render json: {
          errors: ["User was not found or was not logged in."]
        }, status: 404
      end
    end

    def valid_params?(key, val)
      resource_params[:password] && key && val
    end

    def resource_params
      params.permit(devise_parameter_sanitizer.for(:sign_in))
    end

    def get_auth_params
      auth_key = nil
      auth_val = nil

      # iterate thru allowed auth keys, use first found
      resource_class.authentication_keys.each do |k|
        if resource_params[k]
          auth_val = resource_params[k]
          auth_key = k
          break
        end
      end

      # honor devise configuration for case_insensitive_keys
      if resource_class.case_insensitive_keys.include?(auth_key)
        auth_val.downcase!
      end

      return {
        key: auth_key,
        val: auth_val
      }
    end
  end
end
