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

    public function infeasibleShifts(Request $request): Response
    {
        $number_of_hours = (int) $request->getAttribute('number_of_hours');
        $angel_overview = stats_get_needed_angels_overview($number_of_hours);

        $data = [];
        foreach ($angel_overview as $shift) {
            if ($shift['angels_already_signed_up'] == 0 && $shift['needed_angels'] > 0) {
                $data[] = [
                    'title' => $shift['shift_title'],
                    'start' => $shift['shift_start'],
                    'end'   => $shift['shift_end'],
                ];
            }
        }

        usort($data, function ($a, $b) {
            return Carbon::parse($b['start'])->diffInSeconds(Carbon::parse($a['start']));
        });

        return $this->response->withContent(json_encode($data));
    }

    public function cancelledOpeningTimes(Request $request): Response
    {
        $number_of_hours = (int) $request->getAttribute('number_of_hours');
        $angel_overview = stats_get_needed_angels_overview($number_of_hours);

        $cancelled_shifts = [];
        foreach ($angel_overview as $shift) {
            if ($shift['shift_cancelled'] || ($shift['angels_already_signed_up'] == 0 && $shift['needed_angels'] > 0)) {
                if ($shift['shift_cancelled']) {
                    $reason = 'shift_cancelled';
                } else {
                    $reason = 'nobody_in_charge';
                }

                $cancelled_shifts[] = [
                    'title'  => $shift['shift_title'],
                    'start'  => $shift['shift_start'],
                    'end'    => $shift['shift_end'],
                    'reason' => $reason,
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
