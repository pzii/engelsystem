<?php

declare(strict_types=1);

namespace Engelsystem\Controllers\Api;

use Carbon\Carbon;
use Engelsystem\Http\Request;
use Engelsystem\Http\Response;

class PublicController extends ApiController
{
    public array $permissions = [];

    public function index(): Response
    {
        return $this->response
            ->setStatusCode(404)
            ->withContent(json_encode(['message' => 'Not implemented']));
    }

    public function cancelledOpeningTimes(Request $request): Response
    {
        $number_of_hours = (int) $request->getAttribute('number_of_hours');
        return $this->handleCancelledOpeningTimes($number_of_hours, $number_of_hours);
    }

    public function cancelledOpeningTimes2(Request $request): Response
    {
        $hours_advance_noresponsible = (int) $request->getAttribute('hours_advance_noresponsible');
        $hours_advance_cancelled = (int) $request->getAttribute('hours_advance_cancelled');
        return $this->handleCancelledOpeningTimes($hours_advance_cancelled, $hours_advance_noresponsible);
    }

    public function handleCancelledOpeningTimes(int $hrs_adv_cancelled, int $hrs_adv_noresponsible): Response
    {
        $angel_overview = stats_get_needed_angels_overview(max($hrs_adv_cancelled, $hrs_adv_noresponsible));

        $cancelled_shifts = [];
        foreach ($angel_overview as $shift) {
            if (
                $shift['cancel_reason'] !== null
                || ($shift['angels_already_signed_up'] == 0 && $shift['needed_angels'] > 0)
            ) {
                $shift_start = Carbon::parse($shift['shift_start']);
                if ($shift['cancel_reason'] !== null) {
                    $inXhours = Carbon::now()->addHours($hrs_adv_cancelled);
                    if ($shift_start->greaterThan($inXhours)) {
                        continue;
                    }

                    $reason = 'shift_cancelled';
                } else {
                    $inXhours = Carbon::now()->addHours($hrs_adv_noresponsible);
                    if ($shift_start->greaterThan($inXhours)) {
                        continue;
                    }

                    $reason = 'nobody_in_charge';
                }

                $cancelled_shifts[] = [
                    'title'  => $shift['shift_title'],
                    'start'  => $shift['shift_start'],
                    'end'    => $shift['shift_end'],
                    'reason' => $reason,
                    'reason_description' => $shift['cancel_reason'],
                ];
            }
        }

        // Merge consecutive shifts with same title and cancelled reason
        $shifts_per_title = [];
        foreach ($cancelled_shifts as $shift) {
            if (!isset($shifts_per_title[$shift['title']])) {
                $shifts_per_title[$shift['title']] = [];
            }

            $shifts_per_title[$shift['title']][] = $shift;
        }

        $all_shifts = [];
        foreach ($shifts_per_title as $shifts) {
            usort($shifts, function ($a, $b) {
                return Carbon::parse($b['start'])->diffInSeconds(Carbon::parse($a['start']));
            });

            for ($i = 0; $i < count($shifts) - 1; $i++) {
                $end_of_current = Carbon::parse($shifts[$i]['end']);
                $start_of_next = Carbon::parse($shifts[$i + 1]['start']);

                if ($end_of_current->equalTo($start_of_next) && ($shifts[$i]['reason'] == $shifts[$i + 1]['reason'])) {
                    $shifts[$i]['end'] = $shifts[$i + 1]['end'];
                    array_splice($shifts, $i + 1, 1);
                    $i--;
                }
            }

            $all_shifts = array_merge($all_shifts, $shifts);
        }

        // Try to guess leading and trailing times
        $LEAD_TIME_MINUTES = 10;
        $TRAIL_TIME_MINUTES = 20;
        foreach ($all_shifts as &$shift) {
            $start = Carbon::parse($shift['start']);
            $end = Carbon::parse($shift['end']);

            $lead_time = $start->minute == 50 ? $LEAD_TIME_MINUTES : 0;
            $trail_time = $end->minute == 20 ? $TRAIL_TIME_MINUTES : 0;

            $shift['real_start'] = $start->copy()->addMinutes($lead_time)->toDateTimeString();
            $shift['real_end'] = $end->copy()->subMinutes($trail_time)->toDateTimeString();
        }

        usort($all_shifts, function ($a, $b) {
            return Carbon::parse($b['real_start'])->diffInSeconds(Carbon::parse($a['real_start']));
        });

        return $this->response->withContent(json_encode($all_shifts));
    }
}
