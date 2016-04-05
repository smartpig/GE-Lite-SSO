<?php
/*
 Plugin Name: SSO Authentication Lite Edition
 Version: 4.1.7
 Plugin URI:  http://blogs.ge.com
 Description: Authenticate users using SSO Headers. This plugin assumes users are externally authenticated
 Author: Ramprasad Prabhakar 4.1.7 modifications by Lee Cunningham
 Author URI:  http://blogs.ge.com
 */
require_once(dirname(__FILE__) . DIRECTORY_SEPARATOR . 'options-page.php');

class HTTPAuthenticationPlugin {
	var $db_version = 1;
	var $option_name = 'http_authentication_options';
	var $options;
	var $test_data = "test:\n";

	function HTTPAuthenticationPlugin() {
		$this->options = get_option($this->option_name);

		if (is_admin()) {
			$options_page = new HTTPAuthenticationOptionsPage(&$this, $this->option_name, __FILE__, $this->options);
			add_action('admin_init', array(&$this, 'check_options'));
		}
		
		if ($this->options['auto_force_login'] == 1) {
			add_action( 'template_redirect', array(&$this,'force_login'));
		}
		
		add_action('login_head', array(&$this, 'add_login_css'));
		add_action('login_footer', array(&$this, 'add_login_link'));
		add_action('check_passwords', array(&$this, 'generate_password'), 10, 3);
		add_action('wp_logout', array(&$this, 'logout'));
		add_filter('login_url', array(&$this, 'bypass_reauth'));
		add_filter('show_password_fields', array(&$this, 'allow_wp_auth'));
		add_filter('allow_password_reset', array(&$this, 'allow_wp_auth'));
		add_filter('authenticate', array(&$this, 'authenticate'), 10, 3);
		add_action('init', array(&$this, 'check_SSO_matching'));
	}

	function check_SSO_matching(){
		$cookie_user = wp_get_current_user();
		if($cookie_user->user_login != $_SERVER['HTTP_SM_USER'] && $cookie_user->ID != 0){
			$user = $this->check_remote_user();
			//$user = get_user_by('login',$_SERVER['HTTP_SM_USER']);
			//if($user){
				wp_set_current_user($user->ID);					
				//wp_redirect(site_url());
			//}
		}
	}

	/*
	 * Check the options currently in the database and upgrade if necessary.
	 */
	function check_options() {
		if ($this->options === false || ! isset($this->options['db_version']) || $this->options['db_version'] < $this->db_version) {
			if (! is_array($this->options)) {
				$this->options = array();
			}

			$current_db_version = isset($this->options['db_version']) ? $this->options['db_version'] : 0;
			$this->upgrade($current_db_version);
			$this->options['db_version'] = $this->db_version;
			update_option($this->option_name, $this->options);
		}
	}

	/*
	 * Return the correct role based on whether the user has selected to use the roles from lite sso or the blogs default roles.
	 */
	function _get_roles($blog_id = ''){
	
		if(is_multisite()){
			if (!empty($blog_id)) {
				$option = get_blog_option($blog_id, 'http_authentication_options');					
				if(!empty($option['allow_wp_auth_select'])){
					$role = $option['allow_wp_auth_select'];
				}else{
					$role = 'subscriber';
				}                
            } else {			
				$override_default_user_role = $this->options['override_default_user_role'];
				if(!empty($this->options['allow_wp_auth_select'])){
					$role = $this->options['allow_wp_auth_select'];
				}else{
					$role = 'subscriber';
				}
			}
		} else {
			//is single site
			$default_role = get_option('default_role');
			if(!empty($default_role)){
				$role = $default_role;	
			}else{
				$role = 'subscriber';
			}			
		}		
		return $role;
	}

	/*
	 * Upgrade options as needed depending on the current database version.
	 */
	function upgrade($current_db_version) {
		$default_options = array(
			'allow_wp_auth' => false,
			'auth_label' => 'HTTP authentication',
			'login_uri' => htmlspecialchars_decode(wp_login_url()),
			'logout_uri' => remove_query_arg('_wpnonce', htmlspecialchars_decode(wp_logout_url())),
			'auto_create_user' => false,
			'auto_create_email_domain' => '',
			'auto_force_login' => false,
		);

		if ($current_db_version < 1) {
			foreach ($default_options as $key => $value) {
				// Handle migrating existing options from before we stored a db_version
				if (! isset($this->options[$key])) {
					$this->options[$key] = $value;
				}
			}
		}
	}

	function add_login_css() {
		?>
<style type="text/css">
p#http-authentication-link {
	margin: -5em auto 0 auto;
	position: absolute;
	text-align: center;
	width: 100%;
}
</style>
		<?php
	}

	/*
	 * Add a link to the login form to initiate external authentication.
	 */
	function add_login_link() {
		global $redirect_to;

		$login_uri = sprintf($this->options['login_uri'], urlencode($redirect_to));
		$auth_label = $this->options['auth_label'];

		echo "\t" . '<p id="http-authentication-link"><a class="button-primary" href="' . htmlspecialchars($login_uri) . '">Log In with ' . htmlspecialchars($auth_label) . '</a></p>' . "\n";
	}

	/*
	 * Generate a password for the user. This plugin does not require the
	 * administrator to enter this value, but we need to set it so that user
	 * creation and editing works.
	 */
	function generate_password($username, $password1, $password2) {
		if (! $this->allow_wp_auth()) {
			$password1 = $password2 = wp_generate_password();
		}
	}

	/*
	 * Logout the user by redirecting them to the logout URI.
	 */
	function logout() {
		$logout_uri = sprintf($this->options['logout_uri'], urlencode(home_url()));
		// Let's clear the WP AUTH Cookies (and redirect the user to SSO logout URL)
		wp_clear_auth_cookie();
		wp_redirect($logout_uri);
		exit();
	}

	/*
	 * Remove the reauth=1 parameter from the login URL, if applicable. This allows
	 * us to transparently bypass the mucking about with cookies that happens in
	 * wp-login.php immediately after wp_signon when a user e.g. navigates directly
	 * to wp-admin.
	 */
	function bypass_reauth($login_url) {
		$login_url = remove_query_arg('reauth', $login_url);

		return $login_url;
	}

	/*
	 * Can we fallback to built-in WordPress authentication?
	 */
	function allow_wp_auth() {
		return (bool) $this->options['allow_wp_auth'];
	}

	/*
	 * Authenticate the user, first using the external authentication source.
	 * If allowed, fall back to WordPress password authentication.
	 */
	function authenticate($user, $username, $password) {
		$user = $this->check_remote_user();
		if (! is_wp_error($user)) {
			// User was authenticated via REMOTE_USER
			$user = new WP_User($user->ID);
		}
		else {
			// REMOTE_USER is invalid; now what?

			if (! $this->allow_wp_auth()) {
				// Bail with the WP_Error when not falling back to WordPress authentication
				wp_die($user);
			}

			// Fallback to built-in hooks (see wp-includes/user.php)
		}

		return $user;
	}

	/*
	 * If the REMOTE_USER or REDIRECT_REMOTE_USER evironment variable is set, use it
	 * as the username. This assumes that you have externally authenticated the user.
	 */
	function check_remote_user() {
		global $wpdb;

		$username = '';

		#foreach (array('REMOTE_USER', 'REDIRECT_REMOTE_USER') as $key) {
		#	if (isset($_SERVER[$key])) {
		#		$username = $_SERVER[$key];
		#	}
		#}

		if ($_SERVER['HTTP_SM_USER'])
		{
			$username=$_SERVER['HTTP_SM_USER'];
		}
		else
		{
			$username = $_COOKIE['ssouserid'];
		}

		if (! $username)
		{
			return new WP_Error('empty_username', '<strong>ERROR</strong>: No REMOTE_USER or REDIRECT_REMOTE_USER found.');
		}

		$user_cookie = wp_get_current_user();

		// Create new users automatically, if configured
		$user = get_user_by('login',$username);
		if (! $user)  {
			if ((bool) $this->options['auto_create_user']) {
				$user = $this->_create_user($username);	
			}
			else {
				// Bail out to avoid showing the login form
				$user = new WP_Error('authentication_failed', __('<strong>ERROR</strong>: Invalid username or incorrect password.'));
			}
		}
		else{
			//the user exists let's just make sure they exist on this current blog
			$user_id = $user->ID;
			if ( empty( $user->user_email ) ) {
				$user = $this->_update_user($user_id);
			}
			if(function_exists('is_user_member_of_blog')){
				if(!is_user_member_of_blog( $user_id, $blog_id )){
					add_user_to_blog( $blog_id, $user_id, $this->_get_roles() );
				}					
			}				
		}		
		return $user;
	}
	


	/*
	 * Create a new WordPress account for the specified username.
	 */
	function _create_user($username) {
		global $wpdb;

		$password = wp_generate_password();
		$email_domain = $this->options['auto_create_email_domain'];

		require_once( ABSPATH . WPINC . DIRECTORY_SEPARATOR . 'registration.php');
		if ($_SERVER['HTTP_SM_FIRST_NAME'] && $_SERVER['HTTP_SM_LAST_NAME'] && $_SERVER['HTTP_SM_EMAIL'])
		{
			//if user has an apostrophe in their name mail to <uid>@mail.ad.ge.com
			if(strrpos($_SERVER['HTTP_SM_EMAIL'],"'")){
				$user_email = $_SERVER['HTTP_UID']."@mail.ad.ge.com";
			}else{
				$user_email = $_SERVER['HTTP_SM_EMAIL'];
			}
			$disp_name = $_SERVER['HTTP_SM_FIRST_NAME']." ".$_SERVER['HTTP_SM_LAST_NAME'];
			$user_id=wp_insert_user(array ('user_login' => $username, 'user_pass' => $password, 'user_email' => $user_email,'first_name' => $_SERVER['HTTP_SM_FIRST_NAME'],'last_name' => $_SERVER['HTTP_SM_LAST_NAME'],'display_name' => $disp_name ));
			if (is_multisite())
			{

				$blogs = $wpdb->get_results("SELECT * from ".$wpdb->base_prefix."blogs");
				
				foreach ($blogs as $blog)
				{
					$blog_id = $blog->blog_id;
					$role = $this->_get_roles($blog_id);
					add_user_to_blog( $blog_id, $user_id, $role);
				}
				
			}
		}
		else
		{
			$user_id = wp_create_user($username, $password, $username . ($email_domain ? '@' . $email_domain : ''));
			#return new WP_Error('empty_username','Unable to get your information. Please contact the blog admin');
		}
		$user = get_user_by('id', $user_id);

		return $user;
	}

	/*
	 * Update a new WordPress account for the specified username.
	 */
	function _update_user($user_id) {
		global $wpdb;

		require_once( ABSPATH . WPINC . DIRECTORY_SEPARATOR . 'registration.php');
		$disp_name = $_SERVER['HTTP_SM_FIRST_NAME']." ".$_SERVER['HTTP_SM_LAST_NAME'];
		$user_id = wp_update_user( array('ID'=> $user_id, 'user_email'=>$_SERVER['HTTP_SM_EMAIL'], 'first_name'=>$_SERVER['HTTP_SM_FIRST_NAME'], 'last_name'=>$_SERVER['HTTP_SM_LAST_NAME'], 'display_name'=>$disp_name) );
		$user = get_user_by('id', $user_id);

		return $user;
	}
		
	function force_login() { 
		$this->options = get_option($this->option_name);
		$redirect_to = $_SERVER['REQUEST_URI']; // Change this line to change to where logging in redirects the user, i.e. '/', '/wp-admin', etc.
		if (($this->options['ful_feed_protection'] == 0) && strstr($redirect_to,'feed') !== false)  {
			$feed = 0;
        } else {
			$feed = 1;
        }
	
		if ( (! is_user_logged_in())  && $feed == 1 ) {
             $site_url=get_option('siteurl');
             header( 'Location: '.$site_url.'/wp-login.php?redirect_to=' . $redirect_to );
             die();
		}
	}
}

// Load the plugin hooks, etc.
$http_authentication_plugin = new HTTPAuthenticationPlugin();
?>