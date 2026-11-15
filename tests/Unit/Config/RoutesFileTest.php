<?php

declare(strict_types=1);

namespace Engelsystem\Test\Unit\Config;

use Engelsystem\Config\Config;
use Engelsystem\Test\Unit\TestCase;
use FastRoute\Dispatcher;
use FastRoute\RouteCollector;
use PHPUnit\Framework\Attributes\CoversNothing;
use PHPUnit\Framework\Attributes\DoesNotPerformAssertions;

use function FastRoute\simpleDispatcher;

#[CoversNothing]
class RoutesFileTest extends TestCase
{
    protected function setUp(): void
    {
        parent::setUp();

        $config = new Config();
        $this->app->instance('config', $config);
    }

    #[DoesNotPerformAssertions]
    public function testLoadRoutes(): void
    {
        $route = $this->getStubBuilder(RouteCollector::class)
            ->disableOriginalConstructor()
            ->onlyMethods(['addRoute'])
            ->getStub();

        /** @see RouteCollector::addRoute */
        $route->method('addRoute')
            ->willReturnCallback(function ($httpMethod, $route, $handler): void {
                /**
                 * @param string|string[] $httpMethod
                 * @param string          $route
                 * @param mixed           $handler
                 */
                if (is_string($handler) || (is_array($handler) && is_string($handler[0]))) {
                    return;
                }

                $this->fail(
                    sprintf('The route "%s %s" is not cacheable', implode(',', (array) $httpMethod), $route)
                );
            });

        require __DIR__ . '/../../../config/routes.php';
    }

    public function testDisabledFeaturesDoNotRegisterPublicRoutes(): void
    {
        config(array_fill_keys([
            'enable_news',
            'enable_meetings',
            'enable_questions',
            'enable_faq',
            'enable_messages',
        ], false));

        $dispatcher = simpleDispatcher(function (RouteCollector $route): void {
            require __DIR__ . '/../../../config/routes.php';
        });

        $routes = [
            ['GET', '/news'],
            ['GET', '/news/1'],
            ['POST', '/news/1'],
            ['POST', '/news/comment/1'],
            ['GET', '/meetings'],
            ['GET', '/questions'],
            ['POST', '/questions'],
            ['GET', '/questions/new'],
            ['POST', '/questions/new'],
            ['GET', '/faq'],
            ['GET', '/faq/tag/1'],
            ['GET', '/messages'],
            ['POST', '/messages'],
            ['GET', '/messages/1'],
            ['POST', '/messages/1'],
            ['POST', '/messages/1/1'],
        ];

        foreach ($routes as [$method, $path]) {
            $this->assertSame(
                Dispatcher::NOT_FOUND,
                $dispatcher->dispatch($method, $path)[0],
                $method . ' ' . $path
            );
        }
    }
}
