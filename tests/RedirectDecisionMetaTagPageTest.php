<?php

declare(strict_types=1);

namespace Tests;

use PHPUnit\Framework\TestCase;

final class RedirectDecisionMetaTagPageTest extends TestCase
{
    public function testRenderMetaTagPageKeepsEmptyTitleAndDescriptionEmpty(): void
    {
        require_once dirname(__DIR__) . '/src/RedirectDecision/RedirectDecision.php';

        $html = \RedirectDecision::renderMetaTagPage([
            'title' => '   ',
            'description' => null,
            'image' => '',
            'canonical_url' => '',
        ]);

        self::assertStringContainsString('<title></title>', $html);
        self::assertStringContainsString('<meta property="og:title" content="">', $html);
        self::assertStringContainsString('<meta property="og:description" content="">', $html);
        self::assertStringNotContainsString('Shortlink Preview', $html);
        self::assertStringNotContainsString('Crawler receives the meta tag page.', $html);
    }
}
