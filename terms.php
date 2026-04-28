<?php

declare(strict_types=1);

// Terms of Service — required by Facebook App Review
// Accessible at: https://taaw2.one/terms
header('Content-Type: text/html; charset=UTF-8');
header('Cache-Control: public, max-age=86400');
$host = htmlspecialchars($_SERVER['HTTP_HOST'] ?? 'taaw2.one', ENT_QUOTES, 'UTF-8');
$year = date('Y');
?><!DOCTYPE html>
<html lang="en">
<head>
<meta charset="utf-8">
<meta name="viewport" content="width=device-width,initial-scale=1">
<title>Terms of Service — <?=$host?></title>
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
<h1>Terms of Service</h1>
<p class="date">Last updated: <?=$year?>-01-01</p>

<h2>1. Acceptance of Terms</h2>
<p>By accessing or using <?=$host?> ("the Service"), you agree to be bound by these Terms of Service. If you do not agree, do not use the Service.</p>

<h2>2. Description of Service</h2>
<p>The Service provides URL shortening, redirect management, and link analytics. Users can create short links that redirect visitors to specified destination URLs, with Open Graph metadata for social media previews.</p>

<h2>3. User Accounts</h2>
<ul>
<li>You are responsible for maintaining the confidentiality of your account credentials.</li>
<li>You are responsible for all activities that occur under your account.</li>
<li>You must provide accurate information when creating an account.</li>
</ul>

<h2>4. Acceptable Use</h2>
<p>You agree not to use the Service to:</p>
<ul>
<li>Distribute malware, phishing pages, or any malicious content.</li>
<li>Link to content that is illegal, harmful, threatening, abusive, or otherwise objectionable.</li>
<li>Violate any applicable local, national, or international law or regulation.</li>
<li>Infringe upon the intellectual property rights of others.</li>
<li>Send unsolicited bulk messages (spam) using short links.</li>
<li>Attempt to gain unauthorized access to the Service or its related systems.</li>
</ul>

<h2>5. Link Content</h2>
<ul>
<li>You are solely responsible for the destination URLs and metadata (title, description, image) associated with your short links.</li>
<li>We reserve the right to disable or remove any link that violates these terms without prior notice.</li>
<li>We may use automated tools (such as Google Safe Browsing) to scan destination URLs for malicious content.</li>
</ul>

<h2>6. Intellectual Property</h2>
<p>The Service and its original content, features, and functionality are owned by the operator of <?=$host?>. You retain ownership of any content you provide (link metadata, destination URLs).</p>

<h2>7. Third-Party Services</h2>
<p>The Service integrates with third-party platforms including but not limited to Facebook/Meta, Cloudflare, and external URL shortening services. Your use of these integrations is subject to their respective terms of service.</p>

<h2>8. Disclaimer of Warranties</h2>
<p>The Service is provided "as is" and "as available" without warranties of any kind, either express or implied. We do not guarantee that the Service will be uninterrupted, error-free, or free of harmful components.</p>

<h2>9. Limitation of Liability</h2>
<p>To the fullest extent permitted by law, the operator of <?=$host?> shall not be liable for any indirect, incidental, special, consequential, or punitive damages resulting from your use of or inability to use the Service.</p>

<h2>10. Termination</h2>
<p>We may terminate or suspend your account and access to the Service immediately, without prior notice, for conduct that we determine violates these Terms or is harmful to the Service or other users.</p>

<h2>11. Changes to Terms</h2>
<p>We reserve the right to modify these Terms at any time. Changes will be reflected by the "Last updated" date above. Continued use of the Service after changes constitutes acceptance of the new Terms.</p>

<h2>12. Contact</h2>
<p>For questions about these Terms, contact the site administrator at the domain <?=$host?>.</p>

</div>
</body>
</html>
