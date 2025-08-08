<?php
class SecuritySettings {
    public function add_admin_menu() {
        add_menu_page(
            'Security Settings',
            'Security Settings',
            'manage_options',
            'security-settings',
            array($this, 'render_settings_page'),
            'dashicons-shield'
        );
    }

    public function render_settings_page() {
        if (!current_user_can('manage_options')) {
            return;
        }

        if (isset($_POST['save_settings']) && check_admin_referer('security_settings_nonce', 'security_nonce')) {
            $this->save_settings();
            echo '<div class="notice notice-success"><p>Settings saved successfully.</p></div>';
        }

        // Get all options with default values
        $options = array(
            'excluded_paths' => get_option('security_excluded_paths', ''),
            'blocked_patterns' => get_option('security_blocked_patterns', ''),
            'excluded_php_paths' => get_option('security_excluded_php_paths', ''),
            'remove_feeds' => get_option('security_remove_feeds', false),
            'remove_oembed' => get_option('security_remove_oembed', false),
            'remove_pingback' => get_option('security_remove_pingback', false),
            'remove_wp_json' => get_option('security_remove_wp_json', false),
            'remove_rsd' => get_option('security_remove_rsd', false),
            'remove_wp_generator' => get_option('security_remove_wp_generator', false),
            'allow_adsense' => get_option('security_allow_adsense', false),
            'allow_youtube' => get_option('security_allow_youtube', false),
            'allow_twitter' => get_option('security_allow_twitter', false),
            'enable_strict_csp' => get_option('security_enable_strict_csp', false),
            'remove_query_strings' => get_option('security_remove_query_strings', false),
            'cookie_notice_text' => get_option('security_cookie_notice_text', 'This website uses cookies to ensure you get the best experience. By continuing to use this site, you consent to our use of cookies.'),
            'enable_xss' => get_option('security_enable_xss', true),
            'enable_waf' => get_option('security_enable_waf', true),
            'waf_request_limit' => get_option('security_waf_request_limit', 100),
            'waf_blacklist_threshold' => get_option('security_waf_blacklist_threshold', 5),
            'allowed_script_domains' => get_option('security_allowed_script_domains', ''),
            'allowed_style_domains' => get_option('security_allowed_style_domains', ''),
            'allowed_image_domains' => get_option('security_allowed_image_domains', ''),
            'allowed_frame_domains' => get_option('security_allowed_frame_domains', ''),
            'enable_cookie_banner' => get_option('security_enable_cookie_banner', false),
            // SEO and Anti-Spam options
            'max_filter_colours' => get_option('security_max_filter_colours', 3),
            'max_filter_sizes' => get_option('security_max_filter_sizes', 4),
            'max_filter_brands' => get_option('security_max_filter_brands', 2),
            'max_total_filters' => get_option('security_max_total_filters', 8),
            'max_query_params' => get_option('security_max_query_params', 10),
            'max_query_length' => get_option('security_max_query_length', 500),
            '410_page_content' => get_option('security_410_page_content', ''),
            'enable_seo_features' => get_option('security_enable_seo_features', true)
        );
        ?>
        <div class="wrap">
            <h1>Security Settings</h1>
            <form method="post" action="">
                <?php wp_nonce_field('security_settings_nonce', 'security_nonce'); ?>
                
                <h2 class="nav-tab-wrapper">
                    <a href="#security-tab" class="nav-tab nav-tab-active">Security</a>
                    <a href="#seo-tab" class="nav-tab">SEO & Anti-Spam</a>
                    <a href="#csp-tab" class="nav-tab">Content Security Policy</a>
                    <a href="#features-tab" class="nav-tab">WordPress Features</a>
                </h2>

                <div id="security-tab" class="tab-content">
                    <table class="form-table">
                        <tr>
                            <th>Security Features</th>
                            <td>
                                <label>
                                    <input type="checkbox" name="enable_xss" value="1" <?php checked($options['enable_xss']); ?>>
                                    Enable XSS Protection
                                </label>
                                <p class="description">Controls Content Security Policy and other XSS protection features</p>
                            </td>
                        </tr>
                        
                        <tr>
                            <th>WAF Settings</th>
                            <td>
                                <label>
                                    <input type="checkbox" name="enable_waf" value="1" <?php checked($options['enable_waf']); ?>>
                                    Enable Web Application Firewall
                                </label>
                                <p class="description">Protects against common web attacks including SQL injection, XSS, and file inclusion attempts</p>
                                
                                <br><br>
                                <label>
                                    Request Limit per Minute:
                                    <input type="number" name="waf_request_limit" value="<?php echo esc_attr($options['waf_request_limit']); ?>" min="10" max="1000">
                                </label>
                                
                                <br><br>
                                <label>
                                    Blacklist Threshold (violations/24h):
                                    <input type="number" name="waf_blacklist_threshold" value="<?php echo esc_attr($options['waf_blacklist_threshold']); ?>" min="1" max="100">
                                </label>
                            </td>
                        </tr>

                        <tr>
                            <th>Blocked Patterns</th>
                            <td>
                                <textarea name="blocked_patterns" rows="5" cols="50" class="large-text"><?php echo esc_textarea($options['blocked_patterns']); ?></textarea>
                                <p class="description">Enter one pattern per line (e.g., %3C, %3E)</p>
                            </td>
                        </tr>

                        <tr>
                            <th>PHP Access Exclusions</th>
                            <td>
                                <textarea name="excluded_php_paths" rows="5" cols="50" class="large-text"><?php echo esc_textarea($options['excluded_php_paths']); ?></textarea>
                                <p class="description">Enter paths to allow PHP access (e.g., wp-admin, wp-login.php)</p>
                            </td>
                        </tr>
                    </table>
                </div>

                <div id="seo-tab" class="tab-content" style="display:none;">
                    <table class="form-table">
                        <tr>
                            <th>SEO Features</th>
                            <td>
                                <label>
                                    <input type="checkbox" name="enable_seo_features" value="1" <?php checked($options['enable_seo_features']); ?>>
                                    Enable SEO & Anti-Spam Features
                                </label>
                                <p class="description">Enables 410 responses for deleted content and spam URL detection</p>
                            </td>
                        </tr>

                        <tr>
                            <th>Filter Limits (Anti-Spam)</th>
                            <td>
                                <label>
                                    Max Colors in Filter:
                                    <input type="number" name="max_filter_colours" value="<?php echo esc_attr($options['max_filter_colours']); ?>" min="1" max="10">
                                </label>
                                <p class="description">Maximum number of colors allowed in filter_colour parameter</p>
                                
                                <br><br>
                                <label>
                                    Max Sizes in Filter:
                                    <input type="number" name="max_filter_sizes" value="<?php echo esc_attr($options['max_filter_sizes']); ?>" min="1" max="10">
                                </label>
                                <p class="description">Maximum number of sizes allowed in filter_size parameter</p>
                                
                                <br><br>
                                <label>
                                    Max Brands in Filter:
                                    <input type="number" name="max_filter_brands" value="<?php echo esc_attr($options['max_filter_brands']); ?>" min="1" max="10">
                                </label>
                                <p class="description">Maximum number of brands allowed in filter_brand parameter</p>
                                
                                <br><br>
                                <label>
                                    Max Total Filters:
                                    <input type="number" name="max_total_filters" value="<?php echo esc_attr($options['max_total_filters']); ?>" min="1" max="20">
                                </label>
                                <p class="description">Maximum total number of filter values across all parameters</p>
                            </td>
                        </tr>

                        <tr>
                            <th>Query String Limits</th>
                            <td>
                                <label>
                                    Max Query Parameters:
                                    <input type="number" name="max_query_params" value="<?php echo esc_attr($options['max_query_params']); ?>" min="5" max="50">
                                </label>
                                <p class="description">Maximum number of query parameters allowed</p>
                                
                                <br><br>
                                <label>
                                    Max Query String Length:
                                    <input type="number" name="max_query_length" value="<?php echo esc_attr($options['max_query_length']); ?>" min="100" max="2000">
                                </label>
                                <p class="description">Maximum length of query string in characters</p>
                            </td>
                        </tr>

                        <tr>
                            <th>410 Page Content</th>
                            <td>
                                <textarea name="410_page_content" rows="10" cols="50" class="large-text"><?php echo esc_textarea($options['410_page_content']); ?></textarea>
                                <p class="description">Custom HTML content for 410 (Gone) pages. Leave empty for default content.</p>
                            </td>
                        </tr>

                        <tr>
                            <th>Query String Settings</th>
                            <td>
                                <label>
                                    <input type="checkbox" name="remove_query_strings" value="1" <?php checked($options['remove_query_strings']); ?>>
                                    Remove Excessive Query Strings from URLs
                                </label>
                                <p class="description">Automatically removes excessive query parameters while preserving essential WooCommerce filters</p>
                            </td>
                        </tr>
                        
                        <tr>
                            <th>Excluded Paths</th>
                            <td>
                                <textarea name="excluded_paths" rows="5" cols="50" class="large-text"><?php echo esc_textarea($options['excluded_paths']); ?></textarea>
                                <p class="description">Enter one path per line (e.g., /register/?action=check_email). These paths will keep their query strings.</p>
                            </td>
                        </tr>
                    </table>
                </div>

                <div id="csp-tab" class="tab-content" style="display:none;">
                    <table class="form-table">
                        <tr>
                            <th>Content Security Policy Domains</th>
                            <td>
                                <p><strong>Script Domains (script-src)</strong></p>
                                <textarea name="allowed_script_domains" rows="3" cols="50" class="large-text"><?php echo esc_textarea($options['allowed_script_domains']); ?></textarea>
                                <p class="description">Enter one domain per line (e.g., checkout.razorpay.com). These domains will be allowed to load scripts.</p>
                                
                                <br><br>
                                <p><strong>Style Domains (style-src)</strong></p>
                                <textarea name="allowed_style_domains" rows="3" cols="50" class="large-text"><?php echo esc_textarea($options['allowed_style_domains']); ?></textarea>
                                <p class="description">Enter one domain per line for custom style sources.</p>
                                
                                <br><br>
                                <p><strong>Image Domains (img-src)</strong></p>
                                <textarea name="allowed_image_domains" rows="3" cols="50" class="large-text"><?php echo esc_textarea($options['allowed_image_domains']); ?></textarea>
                                <p class="description">Enter one domain per line (e.g., mellmon.in, cdn.razorpay.com). These domains will be allowed to load images.</p>
                                
                                <br><br>
                                <p><strong>Frame Domains (frame-src)</strong></p>
                                <textarea name="allowed_frame_domains" rows="3" cols="50" class="large-text"><?php echo esc_textarea($options['allowed_frame_domains']); ?></textarea>
                                <p class="description">Enter one domain per line for allowed iframe sources.</p>
                            </td>
                        </tr>

                        <tr>
                            <th>Content Security Policy</th>
                            <td>
                                <label>
                                    <input type="checkbox" name="enable_strict_csp" value="1" <?php checked($options['enable_strict_csp']); ?>>
                                    Enable Strict Content Security Policy
                                </label>
                                <p class="description">When disabled, a more permissive policy is used that allows most third-party content. Enable for stricter security.</p>
                                
                                <br><br>
                                <strong>Allow Third-party Services (when strict CSP is enabled):</strong><br>
                                <label>
                                    <input type="checkbox" name="allow_adsense" value="1" <?php checked($options['allow_adsense']); ?>>
                                    Allow Google AdSense
                                </label><br>
                                <label>
                                    <input type="checkbox" name="allow_youtube" value="1" <?php checked($options['allow_youtube']); ?>>
                                    Allow YouTube Embeds
                                </label><br>
                                <label>
                                    <input type="checkbox" name="allow_twitter" value="1" <?php checked($options['allow_twitter']); ?>>
                                    Allow Twitter Embeds
                                </label>
                            </td>
                        </tr>
                    </table>
                </div>

                <div id="features-tab" class="tab-content" style="display:none;">
                    <table class="form-table">
                        <tr>
                            <th>Enable Cookie Consent Banner</th>
                            <td>
                                <label>
                                    <input type="checkbox" name="enable_cookie_banner" value="1" <?php checked($options['enable_cookie_banner']); ?>>
                                    Enable Cookie Consent Banner
                                </label>
                                <p class="description">Show or hide the cookie consent banner on your site.</p>
                            </td>
                        </tr>

                        <tr>
                            <th>Cookie Notice Text</th>
                            <td>
                                <textarea name="cookie_notice_text" rows="3" cols="50" class="large-text"><?php echo esc_textarea($options['cookie_notice_text']); ?></textarea>
                                <p class="description">Customize the cookie consent notice text</p>
                            </td>
                        </tr>
                        
                        <tr>
                            <th>Remove Features</th>
                            <td>
                                <label>
                                    <input type="checkbox" name="remove_feeds" value="1" <?php checked($options['remove_feeds']); ?>>
                                    Remove RSS Feeds (Returns 410 Gone)
                                </label><br>
                                <label>
                                    <input type="checkbox" name="remove_oembed" value="1" <?php checked($options['remove_oembed']); ?>>
                                    Remove oEmbed Links
                                </label><br>
                                <label>
                                    <input type="checkbox" name="remove_pingback" value="1" <?php checked($options['remove_pingback']); ?>>
                                    Remove Pingback and Disable XMLRPC
                                </label><br>
                                <label>
                                    <input type="checkbox" name="remove_wp_json" value="1" <?php checked($options['remove_wp_json']); ?>>
                                    Remove WP REST API Links (wp-json)
                                </label><br>
                                <label>
                                    <input type="checkbox" name="remove_rsd" value="1" <?php checked($options['remove_rsd']); ?>>
                                    Remove RSD Link
                                </label><br>
                                <label>
                                    <input type="checkbox" name="remove_wp_generator" value="1" <?php checked($options['remove_wp_generator']); ?>>
                                    Remove WordPress Generator Meta Tag
                                </label>
                            </td>
                        </tr>
                    </table>
                </div>
                
                <p class="submit">
                    <input type="submit" name="save_settings" class="button button-primary" value="Save Settings">
                </p>
            </form>
        </div>

        <style>
        .nav-tab-wrapper { margin-bottom: 20px; }
        .tab-content { display: none; }
        .tab-content.active { display: block; }
        </style>

        <script>
        jQuery(document).ready(function($) {
            $('.nav-tab').click(function(e) {
                e.preventDefault();
                $('.nav-tab').removeClass('nav-tab-active');
                $('.tab-content').hide();
                $(this).addClass('nav-tab-active');
                $($(this).attr('href')).show();
            });
            
            // Show first tab by default
            $('#security-tab').show();
        });
        </script>
        <?php
    }

    private function save_settings() {
        if (!current_user_can('manage_options')) {
            return;
        }

        if (!isset($_POST['security_nonce']) || !wp_verify_nonce($_POST['security_nonce'], 'security_settings_nonce')) {
            wp_die('Security check failed');
        }

        // Save all settings
        update_option('security_enable_xss', isset($_POST['enable_xss']));
        update_option('security_enable_strict_csp', isset($_POST['enable_strict_csp']));
        update_option('security_allow_adsense', isset($_POST['allow_adsense']));
        update_option('security_allow_youtube', isset($_POST['allow_youtube']));
        update_option('security_allow_twitter', isset($_POST['allow_twitter']));
        update_option('security_cookie_notice_text', sanitize_textarea_field($_POST['cookie_notice_text']));
        update_option('security_excluded_paths', sanitize_textarea_field($_POST['excluded_paths']));
        update_option('security_blocked_patterns', sanitize_textarea_field($_POST['blocked_patterns']));
        update_option('security_excluded_php_paths', sanitize_textarea_field($_POST['excluded_php_paths']));
        update_option('security_remove_feeds', isset($_POST['remove_feeds']));
        update_option('security_remove_oembed', isset($_POST['remove_oembed']));
        update_option('security_remove_pingback', isset($_POST['remove_pingback']));
        update_option('security_remove_wp_json', isset($_POST['remove_wp_json']));
        update_option('security_remove_rsd', isset($_POST['remove_rsd']));
        update_option('security_remove_wp_generator', isset($_POST['remove_wp_generator']));
        update_option('security_enable_waf', isset($_POST['enable_waf']));
        update_option('security_waf_request_limit', intval($_POST['waf_request_limit']));
        update_option('security_waf_blacklist_threshold', intval($_POST['waf_blacklist_threshold']));
        update_option('security_remove_query_strings', isset($_POST['remove_query_strings']));
        update_option('security_allowed_script_domains', sanitize_textarea_field($_POST['allowed_script_domains']));
        update_option('security_allowed_style_domains', sanitize_textarea_field($_POST['allowed_style_domains']));
        update_option('security_allowed_image_domains', sanitize_textarea_field($_POST['allowed_image_domains']));
        update_option('security_allowed_frame_domains', sanitize_textarea_field($_POST['allowed_frame_domains']));
        update_option('security_enable_cookie_banner', isset($_POST['enable_cookie_banner']));
        
        // SEO and Anti-Spam settings
        update_option('security_enable_seo_features', isset($_POST['enable_seo_features']));
        update_option('security_max_filter_colours', intval($_POST['max_filter_colours']));
        update_option('security_max_filter_sizes', intval($_POST['max_filter_sizes']));
        update_option('security_max_filter_brands', intval($_POST['max_filter_brands']));
        update_option('security_max_total_filters', intval($_POST['max_total_filters']));
        update_option('security_max_query_params', intval($_POST['max_query_params']));
        update_option('security_max_query_length', intval($_POST['max_query_length']));
        update_option('security_410_page_content', wp_kses_post($_POST['410_page_content']));
    }

    public function register_settings() {
        $settings = array(
            'security_enable_waf', 'security_enable_xss', 'security_enable_strict_csp',
            'security_allow_adsense', 'security_allow_youtube', 'security_allow_twitter',
            'security_cookie_notice_text', 'security_excluded_paths', 'security_blocked_patterns',
            'security_excluded_php_paths', 'security_remove_feeds', 'security_remove_oembed',
            'security_remove_pingback', 'security_remove_query_strings', 'security_remove_wp_json',
            'security_remove_rsd', 'security_remove_wp_generator', 'security_waf_request_limit',
            'security_waf_blacklist_threshold', 'security_allowed_script_domains',
            'security_allowed_style_domains', 'security_allowed_image_domains',
            'security_allowed_frame_domains', 'security_enable_cookie_banner',
            'security_enable_seo_features', 'security_max_filter_colours',
            'security_max_filter_sizes', 'security_max_filter_brands',
            'security_max_total_filters', 'security_max_query_params',
            'security_max_query_length', 'security_410_page_content'
        );

        foreach ($settings as $setting) {
            register_setting('security_settings', $setting);
        }
    }
}