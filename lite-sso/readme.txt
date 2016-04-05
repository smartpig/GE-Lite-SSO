=== HTTP Authentication ===
Contributors: dwc, Lee Cunningham (4.1.7 release)
Tags: authentication
Requires at least: 3.0
Tested up to: 3.9
Stable tag: 4.0

Use an external authentication source in WordPress.

== Description ==

The HTTP Authentication plugin allows you to use existing means of authenticating people to WordPress. This includes Apache's basic HTTP authentication module and many others.

== Installation ==

1. Login as an existing user, such as admin.
2. Upload the `http-authentication` folder to your plugins folder, usually `wp-content/plugins`. (Or simply via the built-in installer.)
3. Activate the plugin on the Plugins screen.
4. Add one or more users to WordPress, specifying the external username for the Nickname field. Also be sure to set the role for each user.
5. Logout.
6. Protect `wp-login.php` and `wp-admin` using your external authentication (using, for example, `.htaccess` files).
7. Try logging in as one of the users added in step 4.

Note: This version works with WordPress 3.0 and above. Use the following for older versions of WordPress:

* Wordpress 2.0: [Version 1.8](http://downloads.wordpress.org/plugin/http-authentication.1.8.zip)
* Wordpress 2.5 through 2.9.x: [Version 2.4](http://downloads.wordpress.org/plugin/http-authentication.2.4.zip)

== Frequently Asked Questions ==

= What authentication mechanisms can I use? =

Any authentication mechanism which sets the `REMOTE_USER` (or `REDIRECT_REMOTE_USER`, in the case of ScriptAlias'd PHP-as-CGI) environment variable can be used in conjunction with this plugin. Examples include Apache's `mod_auth` and `mod_auth_ldap`.

= How should I set up external authentication? =

This depends on your hosting environment and your means of authentication.

Many Apache installations allow configuration of authentication via `.htaccess` files, while some do not. Try adding the following to your blog's top-level `.htaccess` file:
`<Files wp-login.php>
AuthName "WordPress"
AuthType Basic
AuthUserFile /path/to/passwords
Require user dwc
</Files>`

(You may also want to protect your `xmlrpc.php` file, which uses separate authentication code.)

Then, create another `.htaccess` file in your `wp-admin` directory with the following contents:
`AuthName "WordPress"
AuthType Basic
AuthUserFile /path/to/passwords
Require user dwc`

In both files, be sure to set `/path/to/passwords` to the location of your password file. For more information on creating this file, see below.

= Where can I find more information on configuring Apache authentication? =

See Apache's HOWTO: [Authentication, Authorization, and Access Control](http://httpd.apache.org/docs/howto/auth.html).

= How does this plugin authenticate users? =

This plugin doesn't actually authenticate users. It simply feeds WordPress the name of a user who has successfully authenticated through Apache.

To determine the username, this plugin uses the `REMOTE_USER` or the `REDIRECT_REMOTE_USER` environment variable, which is set by many Apache authentication modules. If someone can find a way to spoof this value, this plugin is not guaranteed to be secure.

By default, this plugin generates a random password each time you create a user or edit an existing user's profile. However, since this plugin requires an external authentication mechanism, this password is not requested by WordPress. Generating a random password helps protect accounts, preventing one authorized user from pretending to be another.

= If I disable this plugin, how will I login? =

Because this plugin generates a random password when you create a new user or edit an existing user's profile, you will most likely have to reset each user's password if you disable this plugin. WordPress provides a link for requesting a new password on the login screen.

Also, you should leave the `admin` user as a fallback, i.e. create a new account to use with this plugin. As long as you don't edit the `admin` profile, WordPress will store the password set when you installed WordPress.

In the worst case scenario, you may have to use phpMyAdmin or the MySQL command line to [reset a user's password](http://codex.wordpress.org/Resetting_Your_Password).

= Can I configure the plugin to support standard WordPress logins? =

Yes. You can authenticate some users via an external, single sign-on system and other users via the built-in username and password combination. (Note: When mixed authentication is in use, this plugin does not scramble passwords as described above.)

When you configure your external authentication system, make sure that you allow users in even if they have not authenticated externally. Using [Shibboleth](http://shibboleth.internet2.edu/) as an example:
`AuthName "Shibboleth"
AuthType Shibboleth
Require Shibboleth`

This enables Shibboleth authentication in ["passive" mode](https://wiki.shibboleth.net/confluence/display/SHIB2/NativeSPProtectContent).

Then, in WordPress:

1. Set the plugin to allow WordPress authentication.
2. Configure the login URI to match your Shibboleth system. For example, if your blog is hosted at `http://example.com/`, then your login URI should be `http://example.com/Shibboleth.sso/Login?target=%s`.
3. Configure the logout URI to match your Shibboleth system. Following the above example, your logout URI would be `http://example.com/Shibboleth.sso/Logout?return=%s`.

After saving the options, authentication will work as follows:

* If a user is already authenticated via Shibboleth, and he or she exists in the WordPress database, this plugin will log them in automatically.
* If a user is not authenticated via Shibboleth, the plugin will present the standard WordPress login form with an additional link to login via Shibboleth.

Other authentication systems (particularly those without a login or logout URI) will need to be configured differently.

= Does this plugin support multisite (WordPress MU) setups? =

Yes, you can enable this plugin across a network or on individual sites. However, options will need to be set on individual sites.

If you have suggestions on how to improve network support, please submit a comment.

== Screenshots ==

1. Plugin options, allowing WordPress authentication
2. WordPress login form with external authentication link

== Changelog ==

= 4.1.7 =
* Added code to allow for updates of user email and names when a name change has been detected.
* Confirmed plugin works in AWS environment setup with SAML and OpenID. Some modifications to Apache may be needed based on version being used to allow headers to pass into web layer.

= 4.0 =
* Restore (and improve) support for falling back to WordPress password authentication
* Remove migration of old options format (we'll assume enough people have upgraded)

= 3.3 =
* Update options handling to better support WordPress MU

= 3.2 =
* Restore password generation for adding and editing users

= 3.1 =
* Bump version number to make 3.0.1 the latest version on wordpress.org

= 3.0.1 =
* Handle authentication cookies more gracefully

= 3.0 =
* Add support for WordPress 3.0
* Update WordPress MU support for WordPress 3.0

= 2.4 =
* Add support for WordPress MU (Elliot Kendall)
* Allow for mixed HTTP and built-in authentication by falling back to wp-login.php (Elliot Kendall)
