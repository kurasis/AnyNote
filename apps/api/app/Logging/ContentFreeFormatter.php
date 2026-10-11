<?php

namespace App\Logging;

use App\Contracts\Catalogue;
use Monolog\Formatter\FormatterInterface;
use Monolog\LogRecord;

final class ContentFreeFormatter implements FormatterInterface
{
    public function format(LogRecord $record): string
    {
        $context = $record->context;
        $out = ['event' => in_array($record->message, ['api.request', 'api.error'], true) ? $record->message : 'application.event'];
        if (isset($context['request_id']) && is_string($context['request_id']) && preg_match('/^[A-Za-z0-9_-]{21}[AQgw]$/D', $context['request_id'])) {
            $out['request_id'] = $context['request_id'];
        }
        if (isset($context['status']) && is_int($context['status']) && $context['status'] >= 100 && $context['status'] <= 599) {
            $out['status'] = $context['status'];
        }
        if (isset($context['method']) && in_array($context['method'], ['GET', 'POST', 'PUT', 'DELETE', 'OPTIONS', 'HEAD'], true)) {
            $out['method'] = $context['method'];
        }
        if (isset($context['elapsed_ms']) && is_int($context['elapsed_ms']) && $context['elapsed_ms'] >= 0 && $context['elapsed_ms'] <= 60000) {
            $out['elapsed_ms'] = $context['elapsed_ms'];
        }
        $routes = array_column(Catalogue::data()['operations'], 'operation_id');
        if (isset($context['route_id']) && in_array($context['route_id'], $routes, true)) {
            $out['route_id'] = $context['route_id'];
        }
        if (isset($context['code']) && in_array($context['code'], array_column(Catalogue::data()['errors']['errors'], 'code'), true)) {
            $out['code'] = $context['code'];
        }

        // No message interpolation, record.extra, exception, URL, IP, identifiers or input.
        return json_encode($out, JSON_THROW_ON_ERROR | JSON_UNESCAPED_SLASHES)."\n";
    }

    public function formatBatch(array $records): string
    {
        return implode('', array_map($this->format(...), $records));
    }
}
