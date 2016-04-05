<?php
class HTTPAuthenticationOptionsPage {
	var $plugin;
	var $group;
	var $page;
	var $options;
	var $title;

	function HTTPAuthenticationOptionsPage($plugin, $group, $page, $options, $title = 'Lite-SSO Authentication') {
		$this->plugin = $plugin;
		$this->group = $group;
		$this->page = $page;
		$this->options = $options;
		$this->title = $title;

		add_action('admin_init', array(&$this, 'register_options'));
		add_action('admin_menu', array(&$this, 'add_options_page'));
	}

	/*
	 * Register the options for this plugin so they can be displayed and updated below.
	 */
	function register_options() {
		register_setting($this->group, $this->group, array(&$this, 'sanitize_settings'));

		$section = 'http_authentication_main';
		add_settings_section($section, 'Main Options', array(&$this, '_display_options_section'), $this->page);
		add_settings_field('http_authentication_allow_wp_auth', 'Allow WordPress authentication?', array(&$this, '_display_option_allow_wp_auth'), $this->page, $section);
		
		if(is_multisite()){
			add_settings_field('http_authentication_display_option_override_default_role','Default User Roles', array(&$this, '_display_option_override_default_role'), $this->page, $section);	
		}
		
		add_settings_field('http_authentication_auth_label', 'Authentication label', array(&$this, '_display_option_auth_label'), $this->page, $section);
		add_settings_field('http_authentication_login_uri', 'Login URI', array(&$this, '_display_option_login_uri'), $this->page, $section);
		add_settings_field('http_authentication_logout_uri', 'Logout URI', array(&$this, '_display_option_logout_uri'), $this->page, $section);
		add_settings_field('http_authentication_auto_create_user', 'Automatically create accounts?', array(&$this, '_display_option_auto_create_user'), $this->page, $section);
		add_settings_field('http_authentication_auto_create_email_domain', 'Email address domain', array(&$this, '_display_option_auto_create_email_domain'), $this->page, $section);
		
		/*added for force-user sso lite integration*/
		add_settings_field('http_authentication_auto_force_user_login', 'Automatically Force User Login?', array(&$this, '_display_option_auto_force_login'), $this->page, $section);
		add_settings_field('http_authentication_auto_force_user_login_feed', 'Login to view feeds ?', array(&$this, '_display_option_ful_feed_protection'), $this->page, $section);
	}

	/*
	 * Set the database version on saving the options.
	 */
	function sanitize_settings($input) {
		$output = $input;
		$output['db_version'] = $this->plugin->db_version;

		return $output;
	}

	/*
	 * Add an options page for this plugin.
	 */
	function add_options_page() {
		add_options_page($this->title, $this->title, 'manage_options', $this->page, array(&$this, '_display_options_page'));
	}

	/*
	 * Display the options for this plugin.
	 */
	function _display_options_page() {
		if (! current_user_can('manage_options')) {
			wp_die(__('You do not have sufficient permissions to access this page.'));
		}
?>
<div class="wrap">
  <h2>Lite-SSO Authentication Options</h2>
  <form action="options.php" method="post">
    <?php settings_errors(); ?>
    <?php settings_fields($this->group); ?>
    <?php do_settings_sections($this->page); ?>
    <p class="submit">
      <input type="submit" name="Submit" value="<?php esc_attr_e('Save Changes'); ?>" class="button-primary" />
    </p>
  </form>
</div>
<?php
	}

	/*
	 * Display explanatory text for the main options section.
	 */
	function _display_options_section() {
	}

	/*
	 * Display the WordPress authentication checkbox.
	 */
	function _display_option_allow_wp_auth() {
		$allow_wp_auth = $this->options['allow_wp_auth'];
		$this->_display_checkbox_field('allow_wp_auth', $allow_wp_auth);
		
	?>
	Should the plugin fallback to WordPress authentication if none is found from the server?
	<?php
		if ($allow_wp_auth && $this->options['login_uri'] == htmlspecialchars_decode(wp_login_url())) {
			echo '<br /><strong>WARNING</strong>: You must set the login URI below to your external authentication system. Otherwise you will not be able to login!';
		}
	}
	
	/*
	 * Displays a checkbox for the Lite SSO 
	 * override blog-level default role for new user
	 */
	 function _display_option_override_default_role(){
		$allow_wp_auth_select = $this->options['allow_wp_auth_select'];
		//delete_option('allow_wp_auth_select');
		$this->_display_options_field('allow_wp_auth_select',
		array(
			'administrator',
			'editor',
			'author',
			'contributor',
			'subscriber'),
			$allow_wp_auth_select,
			is_multisite());
	 }

	/*
	 * Display the authentication label field, describing the authentication system
	 * in use.
	 */
	function _display_option_auth_label() {
		$auth_label = $this->options['auth_label'];
		$this->_display_input_text_field('auth_label', $auth_label);
?>
Default is <code>HTTP authentication</code>; override to use the name of your single sign-on system.
<?php
	}

	/*
	 * Display the login URI field.
	 */
	function _display_option_login_uri() {
		$login_uri = $this->options['login_uri'];
		$this->_display_input_text_field('login_uri', $login_uri);
?>
Default is <code><?php echo wp_login_url(); ?></code>; override to direct users to a single sign-on system.<br />
The string <code>%s</code> will be replaced with the appropriate return URI as provided by WordPress.
<?php
	}

	/*
	 * Display the logout URI field.
	 */
	function _display_option_logout_uri() {
		$logout_uri = $this->options['logout_uri'];
		$this->_display_input_text_field('logout_uri', $logout_uri);
?>
Default is <code><?php echo htmlspecialchars(remove_query_arg('_wpnonce', htmlspecialchars_decode(wp_logout_url()))); ?></code>; override to e.g. remove a cookie.<br />
The string <code>%s</code> will be replaced with your blog's home URI.
<?php
	}

	/*
	 * Display the automatically create accounts checkbox.
	 */
	function _display_option_auto_create_user() {
		$auto_create_user = $this->options['auto_create_user'];
		$this->_display_checkbox_field('auto_create_user', $auto_create_user);
?>
Should a new user be created automatically if not already in the WordPress database?<br />
Created users will obtain the role defined under &quot;New User Default Role&quot; on the <a href="options-general.php">General Options</a> page.
<?php
	}
	/*
	 * Display the email domain field.
	 */
	function _display_option_auto_create_email_domain() {
		$auto_create_email_domain = $this->options['auto_create_email_domain'];
		$this->_display_input_text_field('auto_create_email_domain', $auto_create_email_domain);
?>
When a new user logs in, this domain is used for the initial email address on their account. The user can change his or her email address by editing their profile.
<?php
	}	
	/*
	 * Display the automatically create accounts checkbox.
	 */
	function _display_option_auto_force_login() {
		$auto_force_login = $this->options['auto_force_login'];
		$this->_display_checkbox_field('auto_force_login', $auto_force_login);
?>
Enable force user login
<?php
	}
	function _display_option_ful_feed_protection(){
		$ful_feed_protection = $this->options['ful_feed_protection'];
		$this->_display_radio_field('ful_feed_protection', $ful_feed_protection);
	?>
Enables/Disables mandatory SSO login for viewing feeds.Note: Make sure feed url(s) are excluded from SSO protection(LocalConfig.conf), irrespective of this option.
<?php
	}
	/*
	 * Display a text input field.
	 */
	function _display_input_text_field($name, $value, $size = 75) {
?>
<input type="text" name="<?php echo htmlspecialchars($this->group); ?>[<?php echo htmlspecialchars($name); ?>]" id="http_authentication_<?php echo htmlspecialchars($name); ?>" value="<?php echo htmlspecialchars($value) ?>" size="<?php echo htmlspecialchars($size); ?>" /><br />
<?php
	}

	/*
	 * Display a checkbox field.
	 */
	function _display_checkbox_field($name, $value) {
?>
<input type="checkbox" name="<?php echo htmlspecialchars($this->group); ?>[<?php echo htmlspecialchars($name); ?>]" id="http_authentication_<?php echo htmlspecialchars($name); ?>"<?php if ($value) echo ' checked="checked"' ?> value="1" /><br />
<?php
	}
	
	function _display_options_field($name,$values,$selected,$show){
		if(!(empty($values))){
			?>
			<select name="<?php echo htmlspecialchars($this->group); ?>[<?php echo htmlspecialchars($name); ?>]" id="http_authentication_<?php echo htmlspecialchars($name); ?>"<?php echo (!$show ? ' style="display: none;"' : 'style="display: inline-block;"'); ?>>
				<?php foreach($values as $value){
					?> 
					<option value="<?php echo lcfirst($value); ?>"<?php if(!(empty($selected)) && $selected == $value){ echo ' selected="selected"';} ?> ><?php echo ucfirst($value); ?></option>
					<?php
				}
				?>
			</select>
			<?php
		}
	}
		
	function _display_radio_field($name, $value){?>
		<input type="radio" name="<?php echo htmlspecialchars($this->group)?>[<?php echo htmlspecialchars($name); ?>]" id="http_authentication_<?php echo htmlspecialchars($name); ?>"  <?php if ($value ==1) echo "checked='checked'" ?> value="1">Yes 
		
		<input type="radio" name="<?php echo htmlspecialchars($this->group)?>[<?php echo htmlspecialchars($name); ?>]" id="http_authentication_<?php echo htmlspecialchars($name); ?>"  <?php if ($value ==0) echo "checked='checked'"?> value="0">No
		<br />
	<?php
	}	
	
}
?>