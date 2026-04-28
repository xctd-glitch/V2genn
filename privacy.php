<?php

declare(strict_types=1);

// Privacy Policy — required by Facebook App Review
// Accessible at: https://taaw2.one/privacy
header('Content-Type: text/html; charset=UTF-8');
header('Cache-Control: public, max-age=86400');
$host = htmlspecialchars($_SERVER['HTTP_HOST'] ?? 'taaw2.one', ENT_QUOTES, 'UTF-8');
$year = date('Y');
?><!DOCTYPE html>
<html lang="en">
<head>
<meta charset="utf-8">
<meta name="viewport" content="width=device-width,initial-scale=1">
<title>Privacy Policy — <?=$host?></title>
<style>
*{margin:0;padding:0;box-sizing:border-box}
body{font-family:system-ui,-apple-system,sans-serif;background:#0a0a0a;color:#d4d4d4;line-height:1.7;padding:2rem 1rem}
.container{max-width:680px;margin:0 auto}
h1{font-size:1.5rem;color:#f5f5f5;margin-bottom:.5rem}
h2{font-size:1.1rem;color:#e5e5e5;margin:1.8rem 0 .5rem;border-bottom:1px solid #262626;padding-bottom:.3rem}
p,li{font-size:.9rem;margin-bottom:.6rem}
ul{padding-left:1.2rem}
.date{font-size:.75rem;color:#737373;margin-bottom:2rem}
a{color:#60a5fa;text-decoration:none}
a:hover{text-decoration:underline}
</style>
</head>
<body>
<div class="container">
<h1>Privacy Policy</h1>
<p class="date">Last updated: <?=$year?>-01-01</p>

<h2>1. Introduction</h2>
<p><?=$host?> ("we", "us", "our") operates a URL shortening and redirect service. This policy explains how we handle information when you use our service.</p>

<h2>2. Information We Collect</h2>
<ul>
<li><strong>Link metadata:</strong> When creating short links, users provide a title, description, image URL, and destination URL. This data is stored to generate Open Graph previews.</li>
<li><strong>Click analytics:</strong> We collect anonymous, aggregated click statistics (timestamp, country, referrer) for short links. No personally identifiable information is stored from link visitors.</li>
<li><strong>Account data:</strong> Registered users provide a username and password. Passwords are stored using bcrypt hashing.</li>
</ul>

<h2>3. How We Use Information</h2>
<ul>
<li>To redirect visitors to the intended destination URL.</li>
<li>To display Open Graph previews (title, description, image) when links are shared on social platforms such as Facebook, Twitter, and LinkedIn.</li>
<li>To provide link performance analytics to link creators.</li>
</ul>

<h2>4. Third-Party Services</h2>
<p>We interact with the following third-party services:</p>
<ul>
<li><strong>Facebook / Meta:</strong> We use the Facebook Graph API solely to request Open Graph scraping of short link URLs so that link previews display correctly. No user data is sent to Facebook beyond the public URL of the short link.</li>
<li><strong>Cloudflare:</strong> DNS and CDN services. Subject to <a href="https://www.cloudflare.com/privacypolicy/" target="_blank" rel="noopener">Cloudflare's Privacy Policy</a>.</li>
</ul>

<h2>5. Cookies</h2>
<p>We use a session cookie for authenticated users of the dashboard. We do not use tracking cookies or third-party advertising cookies on short link redirect pages.</p>

<h2>6. Data Retention</h2>
<p>Link data and analytics are retained for as long as the link exists. Users may delete their links at any time, which removes all associated data.</p>

<h2>7. Data Security</h2>
<p>All traffic is served over HTTPS. Passwords are hashed with bcrypt. Database access is restricted to the application server.</p>

<h2>8. Children's Privacy</h2>
<p>Our service is not directed to children under 13. We do not knowingly collect personal information from children.</p>

<h2>9. Changes</h2>
<p>We may update this policy from time to time. Changes will be reflected by the "Last updated" date above.</p>

<h2>10. Contact</h2>
<p>For privacy inquiries, contact the site administrator at the domain <?=$host?>.</p>

</div>
</body>
</html>
