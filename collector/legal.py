"""
Routes pour les pages légales (Privacy Policy, Terms of Service).
"""

from flask import Blueprint, render_template_string, current_app

legal_bp = Blueprint("legal", __name__)

# ═══════════════════════════════════════════════════════════════
# TEMPLATE DE BASE POUR PAGES LÉGALES
# ═══════════════════════════════════════════════════════════════

LEGAL_BASE_TEMPLATE = """
<!DOCTYPE html>
<html lang="en">
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <title>{{ title }} — Cerbere</title>
    <link rel="preconnect" href="https://fonts.googleapis.com">
    <link rel="preconnect" href="https://fonts.gstatic.com" crossorigin>
    <link href="https://fonts.googleapis.com/css2?family=Inter:wght@400;500;600;700&display=swap" rel="stylesheet">
    <style>
        * { margin: 0; padding: 0; box-sizing: border-box; }
        :root {
            --bg-primary: #09090b;
            --bg-secondary: #18181b;
            --border-color: rgba(255, 255, 255, 0.08);
            --text-primary: #fafafa;
            --text-secondary: #a1a1aa;
            --text-muted: #71717a;
            --accent-red: #ef4444;
            --accent-orange: #f97316;
        }
        body {
            font-family: 'Inter', -apple-system, BlinkMacSystemFont, 'Segoe UI', Roboto, sans-serif;
            background: var(--bg-primary);
            color: var(--text-primary);
            line-height: 1.6;
            -webkit-font-smoothing: antialiased;
        }
        .header {
            background: var(--bg-secondary);
            border-bottom: 1px solid var(--border-color);
            padding: 1.5rem 0;
        }
        .header-content {
            max-width: 800px;
            margin: 0 auto;
            padding: 0 2rem;
            display: flex;
            align-items: center;
            gap: 12px;
        }
        .header-content img {
            width: 32px;
            height: 32px;
        }
        .header-content span {
            font-size: 18px;
            font-weight: 700;
            letter-spacing: -0.02em;
        }
        .container {
            max-width: 800px;
            margin: 3rem auto;
            padding: 0 2rem;
        }
        h1 {
            font-size: 36px;
            font-weight: 700;
            margin-bottom: 0.5rem;
            letter-spacing: -0.02em;
            background: linear-gradient(135deg, var(--accent-red) 0%, var(--accent-orange) 100%);
            -webkit-background-clip: text;
            -webkit-text-fill-color: transparent;
            background-clip: text;
        }
        .subtitle {
            color: var(--text-secondary);
            font-size: 15px;
            margin-bottom: 3rem;
        }
        h2 {
            font-size: 24px;
            font-weight: 600;
            margin-top: 2.5rem;
            margin-bottom: 1rem;
            color: var(--text-primary);
        }
        h3 {
            font-size: 18px;
            font-weight: 600;
            margin-top: 2rem;
            margin-bottom: 0.75rem;
            color: var(--text-primary);
        }
        p {
            color: var(--text-secondary);
            margin-bottom: 1rem;
        }
        ul, ol {
            color: var(--text-secondary);
            margin-bottom: 1rem;
            padding-left: 1.5rem;
        }
        li {
            margin-bottom: 0.5rem;
        }
        strong {
            color: var(--text-primary);
            font-weight: 600;
        }
        a {
            color: var(--accent-red);
            text-decoration: none;
            transition: color 0.2s ease;
        }
        a:hover {
            color: var(--accent-orange);
            text-decoration: underline;
        }
        .back-link {
            display: inline-block;
            margin-top: 3rem;
            padding: 12px 24px;
            background: var(--bg-secondary);
            border: 1px solid var(--border-color);
            border-radius: 8px;
            color: var(--text-primary);
            font-weight: 500;
            transition: all 0.2s ease;
        }
        .back-link:hover {
            background: rgba(255, 255, 255, 0.05);
            border-color: var(--accent-red);
            text-decoration: none;
        }
        .footer {
            margin-top: 4rem;
            padding-top: 2rem;
            border-top: 1px solid var(--border-color);
            color: var(--text-muted);
            font-size: 14px;
            text-align: center;
        }
        code {
            background: rgba(255, 255, 255, 0.05);
            padding: 2px 6px;
            border-radius: 4px;
            font-family: 'Courier New', monospace;
            font-size: 14px;
        }
        hr {
            border: none;
            border-top: 1px solid var(--border-color);
            margin: 2rem 0;
        }
    </style>
</head>
<body>
    <header class="header">
        <div class="header-content">
            <img src="/static/logo.svg" alt="Cerbere Logo">
            <span>CERBERE</span>
        </div>
    </header>
    
    <main class="container">
        {% block content %}{% endblock %}
        
        <a href="/login" class="back-link">← Retour à la connexion</a>
        
        <div class="footer">
            <p>© 2026 Cerbere Inc. Tous droits réservés.</p>
        </div>
    </main>
</body>
</html>
"""

# ═══════════════════════════════════════════════════════════════
# PAGE PRIVACY POLICY
# ═══════════════════════════════════════════════════════════════

PRIVACY_HTML = LEGAL_BASE_TEMPLATE.replace(
    "{% block content %}{% endblock %}",
    """
    <h1>Politique de Confidentialité</h1>
    <p class="subtitle">Dernière mise à jour : Septembre 2026</p>

    <p>Cette Politique de Confidentialité explique comment <strong>cerbere Inc</strong> ("Cerbere", "nous", "notre") collecte, utilise et protège les informations lorsque vous utilisez <strong>Cerbere-AG</strong> (également appelé AgentGuard), notre plateforme de sécurité runtime et d'observabilité pour les agents IA (le "Service").</p>

    <hr>

    <h2>1. Qui sommes-nous ?</h2>
    <p>cerbere Inc, situé à Kinshasa, République Démocratique du Congo, opère Cerbere-AG. Pour toute question concernant cette politique ou vos données, contactez-nous à <a href="mailto:hello@cerbereag.site">hello@cerbereag.site</a>.</p>

    <h2>2. Quelles informations collectons-nous ?</h2>

    <h3>2.1 Informations de compte</h3>
    <p>Lorsque vous vous connectez via magic link, Google ou GitHub, nous recevons et stockons :</p>
    <ul>
        <li>Votre adresse email</li>
        <li>Votre nom d'affichage et, si fourni par le fournisseur d'identité, une photo de profil</li>
        <li>Un identifiant de compte unique</li>
        <li>La méthode de connexion utilisée (email, Google ou GitHub)</li>
    </ul>

    <h3>2.2 Informations sur l'organisation et l'équipe</h3>
    <p>Cerbere est multi-tenant : votre compte appartient à une organisation ("org") dans un espace de travail ("tenant"). Nous stockons le nom de l'organisation/espace de travail, les membres associés et le rôle de chaque membre (ex: admin, développeur, observateur).</p>

    <h3>2.3 Données runtime des agents ("spans")</h3>
    <p>La fonction principale du Service est de surveiller les agents IA que vous y connectez. Chaque fois qu'un agent surveillé effectue un appel LLM ou un appel d'outil, nous recevons et stockons un enregistrement "span", qui peut inclure :</p>
    <ul>
        <li>L'entrée envoyée au LLM ou à l'outil (ex: un prompt, un payload d'appel de fonction)</li>
        <li>La sortie retournée</li>
        <li>Les comptages de tokens et le coût estimé</li>
        <li>La latence et les horodatages</li>
        <li>Les résultats de nos vérifications de sécurité automatisées sur cet appel (ex: détection d'injection de prompt, détection de PII/secrets, décisions de politique, scores de risque)</li>
        <li>Les identifiants pour l'agent, la trace et l'organisation qui ont produit le span</li>
    </ul>
    <p><strong>Parce que le contenu des spans peut inclure tout ce que vos agents envoient ou reçoivent, il peut contenir des données personnelles ou des informations confidentielles provenant de vos propres utilisateurs ou systèmes.</strong> Vous êtes responsable de vous assurer que vous avez le droit d'envoyer ce contenu via le Service, et de configurer les fonctionnalités de masquage et de politique du Service de manière appropriée pour votre cas d'utilisation.</p>

    <h3>2.4 Masquage automatisé du contenu</h3>
    <p>Avant que certains contenus de spans soient stockés ou transmis à des services tiers (voir Section 4), nous exécutons une détection automatisée pour identifier et masquer les motifs ressemblant à des secrets (clés API, identifiants, tokens) et les PII courants (emails, numéros de téléphone, numéros d'identification gouvernementaux, numéros de cartes de paiement). Ce processus est au mieux et basé sur des motifs ; il réduit mais n'élimine pas le risque que du contenu sensible soit stocké ou transmis. Ne vous y fiez pas comme seule protection pour des données hautement sensibles.</p>

    <h3>2.5 Journaux d'audit</h3>
    <p>Les actions administratives et liées à la sécurité (connexions, création/révocation d'agents, changements de politique, décisions de contrôle d'accès) sont enregistrées dans un journal d'audit à des fins de sécurité et de conformité.</p>

    <h3>2.6 Données techniques et d'utilisation</h3>
    <p>Nous collectons automatiquement l'adresse IP, les informations sur le navigateur/appareil, les horodatages et les modèles d'utilisation (ex: quelles pages de tableau de bord vous consultez, quels points d'API sont appelés) via la journalisation standard du serveur.</p>

    <h3>2.7 Cookies</h3>
    <p>Nous utilisons un seul cookie de session essentiel, httpOnly, pour vous maintenir connecté. Nous n'utilisons pas de cookies publicitaires ou de suivi tiers. Voir Section 8.</p>

    <h2>3. Comment utilisons-nous les informations ?</h2>
    <p>Nous utilisons les informations ci-dessus pour :</p>
    <ul>
        <li>Vous authentifier et maintenir votre session</li>
        <li>Exploiter la fonction principale du Service : analyser l'activité des agents pour les risques de sécurité et fournir de l'observabilité (tableaux de bord, traces, piste d'audit)</li>
        <li>Appliquer les politiques de sécurité que vous configurez (listes d'autorisation/interdiction d'outils, limites de budget, workflows d'approbation)</li>
        <li>Détecter, enquêter et prévenir les abus, fraudes ou incidents de sécurité</li>
        <li>Fournir du support client</li>
        <li>Maintenir et améliorer la précision de détection du Service</li>
        <li>Respecter les obligations légales et de conformité</li>
        <li>Vous envoyer des communications liées au service (ex: liens de connexion, alertes de sécurité)</li>
    </ul>
    <p><strong>Nous ne vendons pas vos informations personnelles, et nous n'utilisons pas le contenu de vos spans pour entraîner des modèles pour d'autres clients.</strong></p>

    <h2>4. Avec qui partageons-nous les informations ?</h2>
    <p>Nous partageons les informations avec les catégories suivantes de tiers, uniquement selon les besoins pour exploiter le Service :</p>
    <ul>
        <li><strong>Fournisseur d'authentification (Supabase) :</strong> traite la connexion via magic link, Google et GitHub, et stocke votre identité d'authentification.</li>
        <li><strong>Fournisseurs d'hébergement et de base de données :</strong> le Service et sa base de données sont hébergés avec des fournisseurs d'infrastructure (actuellement Render et Supabase/PostgreSQL), qui stockent les données en notre nom selon leurs propres engagements de sécurité.</li>
        <li><strong>Fournisseurs d'analyse de sécurité automatisée :</strong> lorsqu'une analyse de risque plus approfondie est nécessaire, le contenu des spans peut être envoyé à des fournisseurs LLM tiers agissant comme "juge" automatisé pour classer le risque (ex: injection de prompt, violations de politique). Nous appliquons le masquage avant cette étape lorsque possible (voir Section 2.4).</li>
        <li><strong>Fournisseurs d'identité (Google, GitHub) :</strong> si vous vous connectez avec Google ou GitHub, ces fournisseurs traitent votre authentification de leur côté selon leurs propres politiques de confidentialité.</li>
        <li><strong>Légal et sécurité :</strong> nous pouvons divulguer des informations si requis par la loi, un processus légal, ou pour protéger les droits, la propriété ou la sécurité de Cerbere, de nos utilisateurs ou d'autres personnes.</li>
        <li><strong>Transferts d'entreprise :</strong> si Cerbere est impliqué dans une fusion, acquisition ou vente d'actifs, vos informations peuvent être transférées dans le cadre de cette transaction.</li>
    </ul>
    <p><strong>Nous ne partageons pas vos données avec des tiers à leurs propres fins de marketing.</strong></p>

    <h2>5. Conservation des données</h2>
    <p>Nous conservons les informations de compte aussi longtemps que votre compte est actif. Les données de spans, les journaux d'audit et les enregistrements associés sont conservés pendant [PÉRIODE DE CONSERVATION — ex: "90 jours par défaut, ou selon la configuration de votre plan"] pour soutenir les fonctions de sécurité et d'observabilité du Service, à moins qu'une période plus longue ne soit requise par la loi ou un accord signé avec vous. Vous pouvez demander la suppression de votre compte et des données associées comme décrit dans la Section 7.</p>

    <h2>6. Transferts internationaux de données</h2>
    <p>Selon votre emplacement et l'emplacement de nos fournisseurs d'hébergement, vos informations peuvent être transférées et traitées dans des pays autres que le vôtre, y compris les États-Unis. Lorsque requis, nous nous appuyons sur des garanties appropriées (telles que les clauses contractuelles types) pour de tels transferts.</p>

    <h2>7. Vos droits</h2>
    <p>Selon l'endroit où vous vivez, vous pouvez avoir des droits d'accès, de correction, d'exportation ou de suppression de vos données personnelles, ou de vous opposer ou de restreindre certains traitements. Pour exercer ces droits, contactez-nous à <a href="mailto:hello@cerbereag.site">hello@cerbereag.site</a>. Nous répondrons dans le délai requis par la loi applicable.</p>
    <p>Si vous êtes dans l'UE/EEE ou au Royaume-Uni, vous avez également le droit de déposer une plainte auprès de votre autorité locale de protection des données.</p>

    <h2>8. Cookies</h2>
    <p>Nous utilisons un cookie de session essentiel (<code>cerbere_session</code>) pour vous maintenir connecté après une connexion réussie. Il est httpOnly (non lisible par les scripts de page) et expire automatiquement. Nous n'utilisons pas actuellement de cookies d'analyse, publicitaires ou de suivi intersites. Si cela change, cette section sera mise à jour et, lorsque requis, nous vous demanderons d'abord votre consentement.</p>

    <h2>9. Sécurité</h2>
    <p>Nous appliquons des mesures techniques et organisationnelles pour protéger vos données, y compris des connexions chiffrées (HTTPS), des identifiants hachés, un contrôle d'accès basé sur les rôles et la journalisation d'audit. Aucun système n'est entièrement sécurisé, et nous ne pouvons pas garantir une sécurité absolue.</p>

    <h2>10. Confidentialité des enfants</h2>
    <p>Le Service est destiné à un usage professionnel et n'est pas destiné aux personnes de moins de 18 ans. Nous ne collectons pas sciemment d'informations personnelles auprès d'enfants.</p>

    <h2>11. Modifications de cette politique</h2>
    <p>Nous pouvons mettre à jour cette Politique de Confidentialité de temps à autre. Nous mettrons à jour la date de "Dernière mise à jour" ci-dessus et, pour les changements matériels, fournirons un avis supplémentaire (ex: par email ou notification dans l'application).</p>

    <h2>12. Nous contacter</h2>
    <p>
        <strong>cerbere Inc</strong><br>
        Kinshasa, République Démocratique du Congo<br>
        <a href="mailto:hello@cerbereag.site">hello@cerbereag.site</a>
    </p>
    """
)

# ═══════════════════════════════════════════════════════════════
# PAGE TERMS OF SERVICE (à personnaliser selon tes besoins)
# ═══════════════════════════════════════════════════════════════

TERMS_HTML = LEGAL_BASE_TEMPLATE.replace(
    "{% block content %}{% endblock %}",
    """
    <h1>Conditions d'Utilisation</h1>
    <p class="subtitle">Dernière mise à jour : Septembre 2026</p>

    <p>Bienvenue sur <strong>Cerbere-AG</strong> (également appelé AgentGuard). Ces Conditions d'Utilisation ("Conditions") régissent votre utilisation de notre plateforme de sécurité runtime et d'observabilité pour les agents IA (le "Service").</p>

    <hr>

    <h2>1. Acceptation des conditions</h2>
    <p>En accédant ou en utilisant le Service, vous acceptez d'être lié par ces Conditions. Si vous n'acceptez pas ces Conditions, vous ne pouvez pas utiliser le Service.</p>

    <h2>2. Description du Service</h2>
    <p>Cerbere-AG est une plateforme de sécurité runtime pour les agents IA autonomes. Le Service intercepte chaque appel LLM et invocation d'outil, applique des politiques de sécurité multicouches et bloque les menaces en temps réel.</p>

    <h2>3. Éligibilité</h2>
    <p>Vous devez avoir au moins 18 ans pour utiliser le Service. En utilisant le Service, vous déclarez et garantissez que vous avez au moins 18 ans et que vous avez la capacité légale de conclure ces Conditions.</p>

    <h2>4. Compte utilisateur</h2>
    <p>Pour utiliser le Service, vous devez créer un compte. Vous êtes responsable de :</p>
    <ul>
        <li>Maintenir la confidentialité de vos identifiants de compte</li>
        <li>Toutes les activités qui se produisent sous votre compte</li>
        <li>Nous informer immédiatement de toute utilisation non autorisée de votre compte</li>
    </ul>

    <h2>5. Utilisation acceptable</h2>
    <p>Vous acceptez de ne pas utiliser le Service pour :</p>
    <ul>
        <li>Violer toute loi ou réglementation applicable</li>
        <li>Porter atteinte aux droits de propriété intellectuelle d'autrui</li>
        <li>Transmettre des virus, malware ou autre code malveillant</li>
        <li>Tenter d'accéder sans autorisation à nos systèmes ou à ceux de tiers</li>
        <li>Interférer avec ou perturber le Service</li>
        <li>Collecter ou stocker des données personnelles d'autrui sans consentement</li>
    </ul>

    <h2>6. Vos données et contenu</h2>
    <p>Vous conservez tous les droits sur les données et le contenu que vous soumettez au Service ("Votre Contenu"). En soumettant Votre Contenu, vous nous accordez une licence mondiale, non exclusive, libre de droits pour utiliser, reproduire et traiter Votre Contenu uniquement dans la mesure nécessaire pour vous fournir le Service.</p>
    <p>Vous êtes seul responsable de Votre Contenu et vous déclarez et garantissez que :</p>
    <ul>
        <li>Vous possédez ou avez les droits nécessaires sur Votre Contenu</li>
        <li>Vous avez obtenu tous les consentements nécessaires pour les données personnelles incluses dans Votre Contenu</li>
        <li>Votre Contenu ne viole pas les droits de tiers</li>
    </ul>

    <h2>7. Propriété intellectuelle</h2>
    <p>Le Service et son contenu original (à l'exclusion de Votre Contenu), ses fonctionnalités et sa fonctionnalité sont et resteront la propriété exclusive de cerbere Inc et de ses concédants de licence. Le Service est protégé par le droit d'auteur, les marques de commerce et d'autres lois.</p>

    <h2>8. Limitation de responsabilité</h2>
    <p>Dans toute la mesure permise par la loi applicable, en aucun cas cerbere Inc, ses administrateurs, employés, partenaires, agents, fournisseurs ou affiliés ne seront responsables des dommages indirects, accessoires, spéciaux, consécutifs ou punitifs, y compris, sans limitation, la perte de profits, de données, d'utilisation, de clientèle ou d'autres pertes incorporelles, résultant de :</p>
    <ul>
        <li>Votre accès à ou utilisation du (ou incapacité à accéder au ou utiliser le) Service</li>
        <li>Toute conduite ou contenu de tout tiers sur le Service</li>
        <li>Tout contenu obtenu du Service</li>
        <li>Accès ou utilisation non autorisés, altération de vos transmissions ou données</li>
    </ul>

    <h2>9. Exclusion de garantie</h2>
    <p>Le Service est fourni "TEL QUEL" et "TEL QUE DISPONIBLE" sans garanties d'aucune sorte, expresses ou implicites, y compris, mais sans s'y limiter, les garanties implicites de qualité marchande, d'adéquation à un usage particulier et d'absence de contrefaçon.</p>
    <p><strong>Le Service est une couche de sécurité destinée à réduire les risques dans les systèmes d'agents IA. Il ne garantit pas une protection complète contre l'injection de prompt, la fuite de données, l'abus d'outils, les vulnérabilités de modèle ou d'autres attaques. Ne vous fiez pas à Cerbere comme seul contrôle de sécurité pour les infrastructures critiques.</strong></p>

    <h2>10. Résiliation</h2>
    <p>Nous pouvons résilier ou suspendre votre accès au Service immédiatement, sans préavis ni responsabilité, pour toute raison, y compris, sans limitation, si vous violez les Conditions. À la résiliation, votre droit d'utiliser le Service cessera immédiatement.</p>

    <h2>11. Modifications du Service</h2>
    <p>Nous nous réservons le droit, à notre seule discrétion, de modifier ou de remplacer le Service à tout moment. Si une révision est matérielle, nous essaierons de fournir un préavis d'au moins 30 jours avant que de nouvelles conditions ne prennent effet.</p>

    <h2>12. Modifications des Conditions</h2>
    <p>Nous nous réservons le droit, à notre seule discrétion, de modifier ou de remplacer ces Conditions à tout moment. Nous vous informerons de tout changement en publiant les nouvelles Conditions sur cette page et en mettant à jour la date de "Dernière mise à jour".</p>

    <h2>13. Loi applicable</h2>
    <p>Ces Conditions seront régies et interprétées conformément aux lois de la République Démocratique du Congo, sans égard à ses dispositions sur les conflits de lois.</p>

    <h2>14. Nous contacter</h2>
    <p>Si vous avez des questions sur ces Conditions, veuillez nous contacter :</p>
    <p>
        <strong>cerbere Inc</strong><br>
        Kinshasa, République Démocratique du Congo<br>
        <a href="mailto:hello@cerbereag.site">hello@cerbereag.site</a>
    </p>
    """
)

# ═══════════════════════════════════════════════════════════════
# ROUTES
# ═══════════════════════════════════════════════════════════════

@legal_bp.route("/privacy")
def privacy():
    """Page Politique de Confidentialité."""
    return render_template_string(PRIVACY_HTML)

@legal_bp.route("/terms")
def terms():
    """Page Conditions d'Utilisation."""
    return render_template_string(TERMS_HTML)

@legal_bp.route("/legal")
def legal_index():
    """Page d'index des documents légaux."""
    return """
    <!DOCTYPE html>
    <html lang="en">
    <head>
        <meta charset="UTF-8">
        <meta name="viewport" content="width=device-width, initial-scale=1.0">
        <title>Documents Légaux — Cerbere</title>
        <link href="https://fonts.googleapis.com/css2?family=Inter:wght@400;500;600;700&display=swap" rel="stylesheet">
        <style>
            * { margin: 0; padding: 0; box-sizing: border-box; }
            body {
                font-family: 'Inter', sans-serif;
                background: #09090b;
                color: #fafafa;
                min-height: 100vh;
                display: flex;
                flex-direction: column;
                align-items: center;
                justify-content: center;
                padding: 2rem;
            }
            h1 {
                font-size: 36px;
                margin-bottom: 2rem;
                background: linear-gradient(135deg, #ef4444 0%, #f97316 100%);
                -webkit-background-clip: text;
                -webkit-text-fill-color: transparent;
            }
            .links {
                display: flex;
                gap: 1rem;
                flex-wrap: wrap;
                justify-content: center;
            }
            .links a {
                padding: 16px 32px;
                background: #18181b;
                border: 1px solid rgba(255, 255, 255, 0.08);
                border-radius: 8px;
                color: #fafafa;
                text-decoration: none;
                font-weight: 500;
                transition: all 0.2s ease;
            }
            .links a:hover {
                background: rgba(255, 255, 255, 0.05);
                border-color: #ef4444;
            }
            .back {
                margin-top: 3rem;
                color: #a1a1aa;
                text-decoration: none;
            }
            .back:hover {
                color: #fafafa;
            }
        </style>
    </head>
    <body>
        <h1>Documents Légaux</h1>
        <div class="links">
            <a href="/privacy">Politique de Confidentialité</a>
            <a href="/terms">Conditions d'Utilisation</a>
        </div>
        <a href="/login" class="back">← Retour à la connexion</a>
    </body>
    </html>
    """
