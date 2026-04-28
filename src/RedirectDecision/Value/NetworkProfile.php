<?php

declare(strict_types=1);

namespace App\RedirectDecision\Value;

/**
 * @phpstan-type NetworkProfileArray array{
 *     country_code: string,
 *     asn: int,
 *     organization: string,
 *     is_vpn: bool,
 *     is_proxy: bool,
 *     is_hosting: bool,
 *     sources: list<string>
 * }
 */
final class NetworkProfile
{
    /**
     * @param list<string> $sources
     */
    public function __construct(
        private readonly string $countryCode = '',
        private readonly int $asn = 0,
        private readonly string $organization = '',
        private readonly bool $isVpn = false,
        private readonly bool $isProxy = false,
        private readonly bool $isHosting = false,
        private readonly array $sources = []
    ) {
    }

    public function countryCode(): string
    {
        return $this->countryCode;
    }

    public function asn(): int
    {
        return $this->asn;
    }

    public function organization(): string
    {
        return $this->organization;
    }

    public function isVpn(): bool
    {
        return $this->isVpn;
    }

    public function isProxy(): bool
    {
        return $this->isProxy;
    }

    public function isHosting(): bool
    {
        return $this->isHosting;
    }

    /**
     * @return list<string>
     */
    public function sources(): array
    {
        return $this->sources;
    }

    public function isVpnLike(): bool
    {
        return $this->isVpn || $this->isProxy || $this->isHosting;
    }

    public function merge(self $other): self
    {
        return new self(
            $this->countryCode !== '' ? $this->countryCode : $other->countryCode(),
            $this->asn !== 0 ? $this->asn : $other->asn(),
            $this->organization !== '' ? $this->organization : $other->organization(),
            $this->isVpn || $other->isVpn(),
            $this->isProxy || $other->isProxy(),
            $this->isHosting || $other->isHosting(),
            array_values(array_unique(array_merge($this->sources, $other->sources())))
        );
    }

    /**
     * @return NetworkProfileArray
     */
    public function toArray(): array
    {
        return [
            'country_code' => $this->countryCode,
            'asn' => $this->asn,
            'organization' => $this->organization,
            'is_vpn' => $this->isVpn,
            'is_proxy' => $this->isProxy,
            'is_hosting' => $this->isHosting,
            'sources' => $this->sources,
        ];
    }
}
