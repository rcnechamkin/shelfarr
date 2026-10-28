class Current < ActiveSupport::CurrentAttributes
  attribute :session, :api_user, :api_token, :legacy_api_token_authenticated

  def user
    session&.user || api_user
  end

  # A token's power is what its scopes say. Being owned by an admin no longer makes every token an admin token:
  # an admin who mints a `requests:write` token for a script gets a token that acts for the admin only.
  def api_admin?
    legacy_api_token_authenticated || api_token&.has_scope?("requests:admin")
  end

  # May create a request naming another active non-admin user (`username` / `user_id`), and list, show or cancel
  # THAT user's requests when the call names them (`username`). Never retry, grab or blocklist, never see everyone's.
  # For a front end that asks on its members' behalf.
  def api_on_behalf?
    api_admin? || api_token&.has_scope?("requests:on_behalf")
  end

  def api_scope?(scope)
    legacy_api_token_authenticated || api_token&.has_scope?(scope)
  end
end
