<?php
/**
 * Plugin Name: WP PHP Sandbox
 * Description: Éditeur PHP pour utilisateurs connectés (avec protections de base) + support des formulaires de l'élève.
 */

if ( ! defined('ABSPATH') ) {
    exit;
}

/**
 * 1. Route REST
 */
add_action('rest_api_init', function () {
    register_rest_route(
        'sandbox/v1',
        '/run',
        array(
            'methods'             => 'POST',
            'callback'            => 'wpsb_run_code',
            'permission_callback' => 'is_user_logged_in',
        )
    );
});

/**
 * 2. Exécution du code
 */
function wpsb_run_code( $request ) {
    $nonce = $request->get_header('x-wp-nonce');
    if ( ! wp_verify_nonce( $nonce, 'wp_rest' ) ) {
        return rest_ensure_response( array(
            'error' => 'Nonce invalide.',
            'html'  => 'Nonce invalide.',
        ) );
    }

    $code = $request->get_param('code');
    if ( ! $code ) {
        return rest_ensure_response( array(
            'error' => 'Aucun code reçu.',
            'html'  => 'Aucun code reçu.',
        ) );
    }

    // données de formulaire envoyées par le JS
    $form_data = $request->get_param('form');
    if ( is_array($form_data) ) {
        $_POST = $form_data;
    } else {
        $_POST = array();
    }

    if ( strlen( $code ) > 20000 ) {
        return rest_ensure_response( array(
            'error' => 'Code trop long.',
            'html'  => 'Code trop long.',
        ) );
    }

    // ------------- IMPORTANT -------------
    // On enlève "fopen" de la liste générale
    $forbidden = array(
        'exec','shell_exec','system','passthru','proc_open','popen',
        'curl_exec','curl_multi_exec',
        'file_put_contents','fwrite','unlink','rename',
        'require','require_once','include','include_once',
        'eval(','wp-config','__halt_compiler',
    );
    // -------------------------------------

    $lower = strtolower($code);
    foreach ($forbidden as $bad) {
        if ( strpos($lower, strtolower($bad)) !== false ) {
            return rest_ensure_response( array(
                'error' => 'Instruction interdite : ' . $bad,
                'html'  => 'Instruction interdite : ' . $bad,
            ) );
        }
    }

    // Sécurité supplémentaire : autoriser fopen seulement en lecture
    // On bloque si on détecte un mode d'ouverture en écriture
    if ( preg_match('/fopen\s*\([^,]+,\s*[\'"](w|a|x|\+)[^\'"]*[\'"]\s*\)/i', $lower) ) {
        return rest_ensure_response( array(
            'error' => 'Instruction interdite : fopen en écriture',
            'html'  => 'Instruction interdite : fopen en écriture',
        ) );
    }

    ob_start();
    try {
        $runner = function() use ($code) {
            eval('?>' . $code);
        };
        $runner();
    } catch (Throwable $e) {
        echo 'Erreur: ' . $e->getMessage();
    }
    $output = ob_get_clean();

    return rest_ensure_response( array(
        'html' => $output,
    ) );
}

/**
 * 3. Shortcode
 */
function wpsb_shortcode( $atts ) {

    if ( ! is_user_logged_in() ) {
        return 'Vous devez être connecté pour utiliser cet exercice.';
    }

    $default_code = "<?php\necho 'Hello !';\n?>";

    $rest_url = esc_url( rest_url( 'sandbox/v1/run' ) );
    $nonce    = wp_create_nonce( 'wp_rest' );

    ob_start(); ?>
    <style>
        .sandbox-wrap { display:flex; min-height:500px; gap:50px; }
        .sandbox-editor { width:50%; box-sizing:border-box; }
        .sandbox-editor textarea { width:100%; height:400px; font-family:monospace; }
        .sandbox-editor button {
            background: #fff;
            color: #3E63DE;
            border: 2px solid #3E63DE;
            border-radius: 30px;
            padding: 8px 18px;
            font-weight: 600;
            cursor: pointer;
        }
        .sandbox-editor button:hover,
        .sandbox-editor button:active,
        .sandbox-editor button:focus {
            background: #3E63DE !important;
            color: #fff !important;
            outline: none;
        }
        .sandbox-preview iframe { width:100%; height:100%; border:none; }
        .sandbox-error { color:#b00; margin-top:5px; }
    </style>

    <div class="sandbox-wrap">
        <div class="sandbox-editor">
            <textarea id="sandbox-code"><?php echo esc_textarea($default_code); ?></textarea>
            <button id="sandbox-run" type="button">Exécuter</button>
            <div id="sandbox-msg" class="sandbox-error"></div>
        </div>
        <div class="sandbox-preview">
            <iframe id="sandbox-result"></iframe>
        </div>
    </div>

    <script>
    (function(){
        var btn   = document.getElementById('sandbox-run');
        var code  = document.getElementById('sandbox-code');
        var frame = document.getElementById('sandbox-result');
        var msg   = document.getElementById('sandbox-msg');

        function attachFormHandlers() {
            var doc;
            try {
                doc = frame.contentWindow.document;
            } catch(e) {
                return;
            }
            var forms = doc.getElementsByTagName('form');
            for (var i = 0; i < forms.length; i++) {
                (function(form){
                    form.addEventListener('submit', function(e){
                        e.preventDefault();
                        var formData = {};
                        var elements = form.elements;
                        for (var j = 0; j < elements.length; j++) {
                            var el = elements[j];
                            if (!el.name) continue;
                            formData[el.name] = el.value;
                        }
                        runCode(code.value, formData);
                    });
                })(forms[i]);
            }
        }

        function runCode(codeToRun, formObj) {
            msg.textContent = '';
            fetch('<?php echo $rest_url; ?>', {
                method: 'POST',
                headers: {
                    'Content-Type': 'application/json',
                    'X-WP-Nonce': '<?php echo $nonce; ?>'
                },
                body: JSON.stringify({
                    code: codeToRun,
                    form: formObj || null
                })
            })
            .then(function(res) {
                return res.text();
            })
            .then(function(text) {
                var data = null;
                try { data = JSON.parse(text); } catch(e) {}

                var htmlToShow = '';
                if (data && typeof data.html !== 'undefined') {
                    htmlToShow = data.html;
                    if (data.error) {
                        msg.textContent = data.error;
                    }
                } else {
                    htmlToShow = text;
                }

                var doc = frame.contentWindow.document;
                doc.open();
                doc.write(htmlToShow);
                doc.close();

                attachFormHandlers();
            })
            .catch(function(err) {
                msg.textContent = err.message;
            });
        }

        btn.addEventListener('click', function() {
            runCode(code.value, null);
        });
    })();
    </script>
    <?php
    return ob_get_clean();
}
add_shortcode( 'php_sandbox', 'wpsb_shortcode' );
