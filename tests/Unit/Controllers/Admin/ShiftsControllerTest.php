<?php

declare(strict_types=1);

namespace Engelsystem\Test\Unit\Controllers\Admin;

use Engelsystem\Controllers\Admin\ShiftsController;
use Engelsystem\Events\EventDispatcher;
use Engelsystem\Helpers\Authenticator;
use Engelsystem\Helpers\Uuid;
use Engelsystem\Http\Redirector;
use Engelsystem\Http\Request;
use Engelsystem\Models\Shifts\Shift;
use Engelsystem\Models\Shifts\ShiftEntry;
use Engelsystem\Models\User\User;
use Engelsystem\Test\Unit\Controllers\ControllerTest;
use PHPUnit\Framework\MockObject\MockObject;

class ShiftsControllerTest extends ControllerTest
{
    protected Redirector|MockObject $redirect;

    /**
     * @covers \Engelsystem\Controllers\Admin\ShiftsController::__construct
     * @covers \Engelsystem\Controllers\Admin\ShiftsController::history
     */
    public function testHistory(): void
    {
        $this->response->expects($this->once())
            ->method('withView')
            ->willReturnCallback(function (string $view, array $data) {
                $this->assertEquals('admin/shifts/history', $view);
                $this->assertCount(2, $data['shifts'] ?? []);
                return $this->response;
            });

        /** @var ShiftsController $controller */
        $controller = $this->app->make(ShiftsController::class);
        $controller->history();
    }

    /**
     * @covers \Engelsystem\Controllers\Admin\ShiftsController::deleteTransaction
     */
    public function testDeleteTransaction(): void
    {
        $this->database->getConnection()->getRawPdo()->exec('PRAGMA foreign_keys = ON');

        $this->redirect->expects($this->once())
            ->method('back')
            ->willReturn($this->response);
        /** @var Shift $shift */
        $shift = Shift::factory(3)->create(['transaction_id' => Uuid::uuid()])->last();
        ShiftEntry::factory(2)->create(['shift_id' => $shift->id]);

        /** @var EventDispatcher|MockObject $event */
        $event = $this->createMock(EventDispatcher::class);
        $this->app->instance('events.dispatcher', $event);
        $this->setExpects($event, 'dispatch', ['shift.deleting'], [], $this->exactly(3));

        /** @var ShiftsController $controller */
        $controller = $this->app->make(ShiftsController::class);
        $controller->deleteTransaction(new Request([], ['transaction_id' => $shift->transaction_id]));

        $this->assertCount(6, Shift::all());
        $this->assertCount(3, ShiftEntry::all());
        $this->log->hasInfoThatContains('Deleted shift');
        $this->log->hasInfoThatContains('shifts with transaction ID');
        $this->assertHasNotification('shifts.history.delete.success');
    }

    public function setUp(): void
    {
        parent::setUp();

        $this->redirect = $this->createMock(Redirector::class);
        $this->app->instance(Redirector::class, $this->redirect);

        Shift::factory(1)->create(['transaction_id' => null]);
        Shift::factory(4)->create(['transaction_id' => Uuid::uuid()]);
        $shift = Shift::factory(1)->create(['transaction_id' => Uuid::uuid()])->first();

        ShiftEntry::factory(3)->create(['shift_id' => $shift->id]);
    }

    /**
     * @covers \Engelsystem\Controllers\Admin\ShiftsController::toggleCancelled
     */
    public function testToggleCancelledWithReason(): void
    {
        $user = User::factory()->create();

        /** @var Authenticator|MockObject $auth */
        $auth = $this->createMock(Authenticator::class);
        $auth->method('user')->willReturn($user);
        $this->app->instance('authenticator', $auth);

        $this->redirect->expects($this->once())
            ->method('back')
            ->willReturn($this->response);

        $shift = Shift::factory()->create(['cancelled' => false]);

        $request = new Request([], ['cancel_reason' => 'Venue flooded']);
        $request = $request->withAttribute('shift_id', $shift->id);

        /** @var ShiftsController $controller */
        $controller = $this->app->make(ShiftsController::class);
        $controller->toggleCancelled($request);

        $shift->refresh();
        $this->assertTrue($shift->cancelled);
        $this->assertEquals('Venue flooded', $shift->cancel_reason);
        $this->assertHasNotification('shifts.cancelled.success');
    }

    /**
     * @covers \Engelsystem\Controllers\Admin\ShiftsController::toggleCancelled
     */
    public function testToggleEnabledClearsReason(): void
    {
        $user = User::factory()->create();

        /** @var Authenticator|MockObject $auth */
        $auth = $this->createMock(Authenticator::class);
        $auth->method('user')->willReturn($user);
        $this->app->instance('authenticator', $auth);

        $this->redirect->expects($this->once())
            ->method('back')
            ->willReturn($this->response);

        $shift = Shift::factory()->create(['cancelled' => true, 'cancel_reason' => 'Some reason']);

        $request = new Request();
        $request = $request->withAttribute('shift_id', $shift->id);

        /** @var ShiftsController $controller */
        $controller = $this->app->make(ShiftsController::class);
        $controller->toggleCancelled($request);

        $shift->refresh();
        $this->assertFalse($shift->cancelled);
        $this->assertEquals('', $shift->cancel_reason);
        $this->assertHasNotification('shifts.enabled.success');
    }
}
