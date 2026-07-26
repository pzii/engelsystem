<?php

declare(strict_types=1);

namespace Engelsystem\Controllers\Api;

use Engelsystem\Controllers\BaseController;
use Engelsystem\Http\Response;

abstract class ApiController extends BaseController
{
    public array $permissions = [
        'api',
    ];

    public function __construct(protected Response $response)
    {
        $this->response = $this->response
            ->withHeader('content-type', 'application/json');

        $origin = $this->getApiCorsOrigin();
        if (!is_null($origin)) {
            $this->response = $this->response
                ->withHeader('access-control-allow-origin', $origin)
                ->withHeader('vary', 'Origin');
        }
    }

    protected function getApiCorsOrigin(): ?string
    {
        $url = config('url');
        if (!is_string($url)) {
            return null;
        }

        $parts = parse_url($url);
        if (!is_array($parts) || empty($parts['scheme']) || empty($parts['host'])) {
            return null;
        }

        $origin = $parts['scheme'] . '://' . $parts['host'];
        if (!empty($parts['port'])) {
            $origin .= ':' . (int) $parts['port'];
        }

        return $origin;
    }
}
