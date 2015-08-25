module DeviseTokenAuth
  class RegistrationsController < DeviseTokenAuth::ApplicationController
    before_filter :set_user_by_token, :only => [:destroy, :update]
    before_filter :validate_sign_up_params, :only => :create
    before_filter :validate_account_update_params, :only => :update
    skip_after_filter :update_auth_header, :only => [:create, :destroy]

    def create
      @resource            = resource_class.new(resource_params)
      @resource.provider   = "email"
      @resource.admin      = true
      organization         = Organization.new(name: params[:organization_name], phone: params[:organization_phone])
      @resource.organization = organization
      # give redirect value from params priority
      
      redirect_url = params[:confirm_success_url]

      # fall back to default value if provided
      redirect_url ||= DeviseTokenAuth.default_confirm_success_url

      # success redirect url is required
      if resource_class.devise_modules.include?(:confirmable) && !redirect_url
        return render json: {
          status: 'error',
          data:   @resource.as_json,
          errors: ["Missing `confirm_success_url` param."]
        }, status: 403
      end

      # if whitelist is set, validate redirect_url against whitelist
      if DeviseTokenAuth.redirect_whitelist
        unless DeviseTokenAuth.redirect_whitelist.include?(redirect_url)
          return render json: {
            status: 'error',
            data:   @resource.as_json,
            errors: ["Redirect to #{redirect_url} not allowed."]
          }, status: 403
        end
      end

      begin
        # override email confirmation, must be sent manually from ctrl
        resource_class.skip_callback("create", :after, :send_on_create_confirmation_instructions)

        organization.save if @resource.valid?
        
        if @resource.save
          if Rails.env.production?
            begin
              gibbon = Gibbon::Request.new(api_key: ENV["MAILCHIMP_API_KEY"])
              gibbon.lists(ENV["MAILCHIMP_LIST_ID"]).members.create(body: { email_address: @resource.email, status: "subscribed", merge_fields: {}, :double_optin => false })
            rescue Gibbon::MailChimpError
            end
            
            Hubspot::Contact.create!(@resource.email, {firstname: @resource.first_name, lastname: @resource.last_name, phone: organization.phone})
          end

          yield @resource if block_given?

          unless @resource.confirmed?
            # user will require email authentication
            @resource.send_confirmation_instructions({
              client_config: params[:config_name],
              redirect_url: redirect_url
            })

          else
            # email auth has been bypassed, authenticate user
            @client_id = SecureRandom.urlsafe_base64(nil, false)
            @token     = SecureRandom.urlsafe_base64(nil, false)

            @resource.tokens[@client_id] = {
              token: BCrypt::Password.create(@token),
              expiry: (Time.now + DeviseTokenAuth.token_lifespan).to_i
            }

            @resource.save!

            update_auth_header
          end

          UserMailer.email_terms(@resource).deliver! if params[:email_terms]

          render json: {
            status: 'success',
            data:   @resource.as_json
          }
        else
          clean_up_passwords @resource
          render json: {
            status: 'error',
            data:   @resource.as_json,
            errors: @resource.errors.to_hash.merge(full_messages: @resource.errors.full_messages)
          }, status: 403
        end
      rescue ActiveRecord::RecordNotUnique
        clean_up_passwords @resource
        render json: {
          status: 'error',
          data:   @resource.as_json,
          errors: ["An account already exists for #{@resource.email}"]
        }, status: 403
      end
    end

    def update
      if @resource

        if @resource.update_attributes(account_update_params)
          yield @resource if block_given?
          render json: {
            status: 'success',
            data:   @resource.as_json
          }
        else
          render json: {
            status: 'error',
            errors: @resource.errors.to_hash.merge(full_messages: @resource.errors.full_messages)
          }, status: 403
        end
      else
        render json: {
          status: 'error',
          errors: ["User not found."]
        }, status: 404
      end
    end

    def destroy
      if @resource
        @resource.destroy
        yield @resource if block_given?

        render json: {
          status: 'success',
          message: "Account with uid #{@resource.uid} has been destroyed."
        }
      else
        render json: {
          status: 'error',
          errors: ["Unable to locate account for destruction."]
        }, status: 404
      end
    end

    def resource_params
      params.permit(:email, :password, :password_confirmation, :username, :first_name, :last_name, :work_phone)
    end

    def sign_up_params
      params.permit(devise_parameter_sanitizer.for(:sign_up))
    end

    def account_update_params
      params.permit(devise_parameter_sanitizer.for(:account_update))
    end

    private

    def validate_sign_up_params
      validate_post_data sign_up_params, 'Please submit proper sign up data in request body.'
    end

    def validate_account_update_params
      validate_post_data account_update_params, 'Please submit proper account update data in request body.'
    end

    def validate_post_data which, message
      render json: {
         status: 'error',
         errors: [message]
      }, status: :unprocessable_entity if which.empty?
    end
  end
end
