<?php

namespace App\Http\Controllers;

use App\Http\Controllers\Controller;
use App\Models\AuditLog;
use App\Models\ErrorLog;
use App\Models\ActivityLog;
use Illuminate\Http\Request;

class LogController extends Controller
{
    // Activity Logs (existing)
    public function getActivityLogs(Request $request)
    {
        try {
            $query = ActivityLog::query();

            // Filter by user
            if ($request->has('user_id')) {
                $query->where('user_id', $request->user_id);
            }

            // Filter by action
            if ($request->has('action')) {
                $query->where('action', 'like', '%' . $request->action . '%');
            }

            // Filter by date range
            if ($request->has('from_date')) {
                $query->whereDate('created_at', '>=', $request->from_date);
            }

            if ($request->has('to_date')) {
                $query->whereDate('created_at', '<=', $request->to_date);
            }

            $perPage = $request->get('per_page', 15);
            $logs = $query->orderBy('created_at', 'desc')->paginate($perPage);

            return response()->json([
                'success' => true,
                'data' => $logs,
                'message' => 'Activity logs retrieved successfully'
            ], 200);

        } catch (\Exception $e) {
            return response()->json([
                'success' => false,
                'message' => 'Failed to retrieve activity logs',
                'error' => $e->getMessage()
            ], 500);
        }
    }

    // Audit Logs
    public function getAuditLogs(Request $request)
    {
        try {
            $query = AuditLog::with('user:id,name,email');

            // Filter by user
            if ($request->has('user_id')) {
                $query->where('user_id', $request->user_id);
            }

            // Filter by table
            if ($request->has('table_name')) {
                $query->where('table_name', $request->table_name);
            }

            // Filter by record
            if ($request->has('record_id')) {
                $query->where('record_id', $request->record_id);
            }

            // Filter by action
            if ($request->has('action')) {
                $query->where('action', $request->action);
            }

            // Filter by date range
            if ($request->has('from_date')) {
                $query->whereDate('created_at', '>=', $request->from_date);
            }

            if ($request->has('to_date')) {
                $query->whereDate('created_at', '<=', $request->to_date);
            }

            $perPage = $request->get('per_page', 15);
            $logs = $query->orderBy('created_at', 'desc')->paginate($perPage);

            // Log this activity
            ActivityLog::createLog([
                'user_id' => $request->user()->id,
                'action' => 'audit_logs_viewed',
                'table_name' => 'audit_logs',
                'response_status' => 200,
            ]);

            return response()->json([
                'success' => true,
                'data' => $logs,
                'message' => 'Audit logs retrieved successfully'
            ], 200);

        } catch (\Exception $e) {
            ErrorLog::logException($e, $request->user()->id);
            
            return response()->json([
                'success' => false,
                'message' => 'Failed to retrieve audit logs',
                'error' => $e->getMessage()
            ], 500);
        }
    }

    // Error Logs
    public function getErrorLogs(Request $request)
    {
        try {
            $query = ErrorLog::with('user:id,name,email');

            // Filter by user
            if ($request->has('user_id')) {
                $query->where('user_id', $request->user_id);
            }

            // Filter by error type
            if ($request->has('error_type')) {
                $query->where('error_type', 'like', '%' . $request->error_type . '%');
            }

            // Filter by status code
            if ($request->has('status_code')) {
                $query->where('status_code', $request->status_code);
            }

            // Filter by message
            if ($request->has('search')) {
                $query->where('message', 'like', '%' . $request->search . '%');
            }

            // Filter by date range
            if ($request->has('from_date')) {
                $query->whereDate('created_at', '>=', $request->from_date);
            }

            if ($request->has('to_date')) {
                $query->whereDate('created_at', '<=', $request->to_date);
            }

            $perPage = $request->get('per_page', 15);
            $logs = $query->orderBy('created_at', 'desc')->paginate($perPage);

            // Log this activity
            ActivityLog::createLog([
                'user_id' => $request->user()->id,
                'action' => 'error_logs_viewed',
                'table_name' => 'error_logs',
                'response_status' => 200,
            ]);

            return response()->json([
                'success' => true,
                'data' => $logs,
                'message' => 'Error logs retrieved successfully'
            ], 200);

        } catch (\Exception $e) {
            ErrorLog::logException($e, $request->user()->id);
            
            return response()->json([
                'success' => false,
                'message' => 'Failed to retrieve error logs',
                'error' => $e->getMessage()
            ], 500);
        }
    }

    // Get Audit History for Specific Record
    public function getRecordAuditHistory(Request $request, $tableName, $recordId)
    {
        try {
            $logs = AuditLog::getRecordHistory($tableName, $recordId);

            // Log this activity
            ActivityLog::createLog([
                'user_id' => $request->user()->id,
                'action' => 'record_audit_history_viewed',
                'table_name' => $tableName,
                'record_id' => $recordId,
                'response_status' => 200,
            ]);

            return response()->json([
                'success' => true,
                'data' => $logs,
                'message' => 'Record audit history retrieved successfully',
                'meta' => [
                    'table_name' => $tableName,
                    'record_id' => $recordId,
                    'total_changes' => $logs->count()
                ]
            ], 200);

        } catch (\Exception $e) {
            ErrorLog::logException($e, $request->user()->id);
            
            return response()->json([
                'success' => false,
                'message' => 'Failed to retrieve record audit history',
                'error' => $e->getMessage()
            ], 500);
        }
    }

    // Get Error Statistics
    public function getErrorStatistics(Request $request)
    {
        try {
            $startDate = $request->get('from_date');
            $endDate = $request->get('to_date');

            $statistics = ErrorLog::getStatistics($startDate, $endDate);

            // Log this activity
            ActivityLog::createLog([
                'user_id' => $request->user()->id,
                'action' => 'error_statistics_viewed',
                'table_name' => 'error_logs',
                'response_status' => 200,
            ]);

            return response()->json([
                'success' => true,
                'data' => $statistics,
                'message' => 'Error statistics retrieved successfully',
                'meta' => [
                    'date_range' => [
                        'from' => $startDate,
                        'to' => $endDate
                    ]
                ]
            ], 200);

        } catch (\Exception $e) {
            ErrorLog::logException($e, $request->user()->id);
            
            return response()->json([
                'success' => false,
                'message' => 'Failed to retrieve error statistics',
                'error' => $e->getMessage()
            ], 500);
        }
    }

    // Get Audit Statistics
    public function getAuditStatistics(Request $request)
    {
        try {
            $startDate = $request->get('from_date');
            $endDate = $request->get('to_date');

            $statistics = AuditLog::getStatistics($startDate, $endDate);

            // Log this activity
            ActivityLog::createLog([
                'user_id' => $request->user()->id,
                'action' => 'audit_statistics_viewed',
                'table_name' => 'audit_logs',
                'response_status' => 200,
            ]);

            return response()->json([
                'success' => true,
                'data' => $statistics,
                'message' => 'Audit statistics retrieved successfully',
                'meta' => [
                    'date_range' => [
                        'from' => $startDate,
                        'to' => $endDate
                    ]
                ]
            ], 200);

        } catch (\Exception $e) {
            ErrorLog::logException($e, $request->user()->id);
            
            return response()->json([
                'success' => false,
                'message' => 'Failed to retrieve audit statistics',
                'error' => $e->getMessage()
            ], 500);
        }
    }

    // Get Critical Errors
    public function getCriticalErrors(Request $request)
    {
        try {
            $limit = $request->get('limit', 50);
            $errors = ErrorLog::getCriticalErrors($limit);

            // Log this activity
            ActivityLog::createLog([
                'user_id' => $request->user()->id,
                'action' => 'critical_errors_viewed',
                'table_name' => 'error_logs',
                'response_status' => 200,
            ]);

            return response()->json([
                'success' => true,
                'data' => $errors,
                'message' => 'Critical errors retrieved successfully'
            ], 200);

        } catch (\Exception $e) {
            ErrorLog::logException($e, $request->user()->id);
            
            return response()->json([
                'success' => false,
                'message' => 'Failed to retrieve critical errors',
                'error' => $e->getMessage()
            ], 500);
        }
    }

    // Get Errors by Type
    public function getErrorsByType(Request $request, $errorType)
    {
        try {
            $limit = $request->get('limit', 50);
            $errors = ErrorLog::getErrorsByType($errorType, $limit);

            // Log this activity
            ActivityLog::createLog([
                'user_id' => $request->user()->id,
                'action' => 'errors_by_type_viewed',
                'table_name' => 'error_logs',
                'response_data' => ['error_type' => $errorType],
                'response_status' => 200,
            ]);

            return response()->json([
                'success' => true,
                'data' => $errors,
                'message' => "Errors of type '{$errorType}' retrieved successfully",
                'meta' => [
                    'error_type' => $errorType,
                    'total_found' => $errors->count()
                ]
            ], 200);

        } catch (\Exception $e) {
            ErrorLog::logException($e, $request->user()->id);
            
            return response()->json([
                'success' => false,
                'message' => 'Failed to retrieve errors by type',
                'error' => $e->getMessage()
            ], 500);
        }
    }

    // Clean Old Logs
    public function cleanOldLogs(Request $request)
    {
        try {
            $days = $request->get('days', 30);
            
            $deletedErrorLogs = ErrorLog::cleanOldLogs($days);
            
            // You might want to also clean audit logs based on your retention policy
            // $deletedAuditLogs = AuditLog::where('created_at', '<', now()->subDays($days))->delete();

            // Log this activity
            ActivityLog::createLog([
                'user_id' => $request->user()->id,
                'action' => 'old_logs_cleaned',
                'response_data' => [
                    'days' => $days,
                    'deleted_error_logs' => $deletedErrorLogs,
                ],
                'response_status' => 200,
            ]);

            return response()->json([
                'success' => true,
                'message' => 'Old logs cleaned successfully',
                'data' => [
                    'days' => $days,
                    'deleted_error_logs' => $deletedErrorLogs,
                ]
            ], 200);

        } catch (\Exception $e) {
            ErrorLog::logException($e, $request->user()->id);
            
            return response()->json([
                'success' => false,
                'message' => 'Failed to clean old logs',
                'error' => $e->getMessage()
            ], 500);
        }
    }

    // Get Log Summary Dashboard
    public function getLogSummary(Request $request)
    {
        try {
            $startDate = $request->get('from_date', now()->subDays(7));
            $endDate = $request->get('to_date', now());

            $summary = [
                'activity_logs' => [
                    'total' => ActivityLog::whereBetween('created_at', [$startDate, $endDate])->count(),
                    'unique_users' => ActivityLog::whereBetween('created_at', [$startDate, $endDate])
                        ->distinct('user_id')->count('user_id'),
                    'top_actions' => ActivityLog::whereBetween('created_at', [$startDate, $endDate])
                        ->selectRaw('action, COUNT(*) as count')
                        ->groupBy('action')
                        ->orderBy('count', 'desc')
                        ->limit(5)
                        ->pluck('count', 'action'),
                ],
                'audit_logs' => [
                    'total' => AuditLog::whereBetween('created_at', [$startDate, $endDate])->count(),
                    'by_action' => AuditLog::whereBetween('created_at', [$startDate, $endDate])
                        ->selectRaw('action, COUNT(*) as count')
                        ->groupBy('action')
                        ->pluck('count', 'action'),
                    'by_table' => AuditLog::whereBetween('created_at', [$startDate, $endDate])
                        ->selectRaw('table_name, COUNT(*) as count')
                        ->groupBy('table_name')
                        ->orderBy('count', 'desc')
                        ->limit(5)
                        ->pluck('count', 'table_name'),
                    'unique_users' => AuditLog::whereBetween('created_at', [$startDate, $endDate])
                        ->distinct('user_id')->count('user_id'),
                ],
                'error_logs' => [
                    'total' => ErrorLog::whereBetween('created_at', [$startDate, $endDate])->count(),
                    'critical_errors' => ErrorLog::whereBetween('created_at', [$startDate, $endDate])
                        ->whereBetween('status_code', [500, 599])->count(),
                    'by_type' => ErrorLog::whereBetween('created_at', [$startDate, $endDate])
                        ->selectRaw('error_type, COUNT(*) as count')
                        ->groupBy('error_type')
                        ->orderBy('count', 'desc')
                        ->limit(5)
                        ->pluck('count', 'error_type'),
                    'by_status_code' => ErrorLog::whereBetween('created_at', [$startDate, $endDate])
                        ->whereNotNull('status_code')
                        ->selectRaw('status_code, COUNT(*) as count')
                        ->groupBy('status_code')
                        ->orderBy('count', 'desc')
                        ->pluck('count', 'status_code'),
                ],
                'date_range' => [
                    'from' => $startDate,
                    'to' => $endDate
                ]
            ];

            // Log this activity
            ActivityLog::createLog([
                'user_id' => $request->user()->id,
                'action' => 'log_summary_viewed',
                'response_status' => 200,
            ]);

            return response()->json([
                'success' => true,
                'data' => $summary,
                'message' => 'Log summary retrieved successfully'
            ], 200);

        } catch (\Exception $e) {
            ErrorLog::logException($e, $request->user()->id);
            
            return response()->json([
                'success' => false,
                'message' => 'Failed to retrieve log summary',
                'error' => $e->getMessage()
            ], 500);
        }
    }

    // Export Logs (CSV format)
    public function exportLogs(Request $request)
    {
        try {
            $type = $request->get('type', 'activity'); // activity, audit, error
            $startDate = $request->get('from_date');
            $endDate = $request->get('to_date');
            $format = $request->get('format', 'csv'); // csv, json

            $data = [];
            $filename = '';

            switch ($type) {
                case 'activity':
                    $query = ActivityLog::query();
                    if ($startDate) $query->whereDate('created_at', '>=', $startDate);
                    if ($endDate) $query->whereDate('created_at', '<=', $endDate);
                    $data = $query->orderBy('created_at', 'desc')->get();
                    $filename = 'activity_logs_' . now()->format('Y_m_d_H_i_s');
                    break;

                case 'audit':
                    $query = AuditLog::with('user:id,name,email');
                    if ($startDate) $query->whereDate('created_at', '>=', $startDate);
                    if ($endDate) $query->whereDate('created_at', '<=', $endDate);
                    $data = $query->orderBy('created_at', 'desc')->get();
                    $filename = 'audit_logs_' . now()->format('Y_m_d_H_i_s');
                    break;

                case 'error':
                    $query = ErrorLog::with('user:id,name,email');
                    if ($startDate) $query->whereDate('created_at', '>=', $startDate);
                    if ($endDate) $query->whereDate('created_at', '<=', $endDate);
                    $data = $query->orderBy('created_at', 'desc')->get();
                    $filename = 'error_logs_' . now()->format('Y_m_d_H_i_s');
                    break;

                default:
                    return response()->json([
                        'success' => false,
                        'message' => 'Invalid log type specified'
                    ], 400);
            }

            // Log this activity
            ActivityLog::createLog([
                'user_id' => $request->user()->id,
                'action' => 'logs_exported',
                'response_data' => [
                    'type' => $type,
                    'format' => $format,
                    'records_count' => $data->count(),
                    'date_range' => ['from' => $startDate, 'to' => $endDate]
                ],
                'response_status' => 200,
            ]);

            if ($format === 'json') {
                return response()->json([
                    'success' => true,
                    'data' => $data,
                    'message' => 'Logs exported successfully',
                    'meta' => [
                        'type' => $type,
                        'total_records' => $data->count(),
                        'exported_at' => now()->toISOString()
                    ]
                ], 200);
            }

            // For CSV format, you would typically generate and return a file
            // This is a simplified version returning structured data
            return response()->json([
                'success' => true,
                'message' => 'Logs ready for export',
                'data' => [
                    'filename' => $filename . '.csv',
                    'total_records' => $data->count(),
                    'download_url' => '/api/logs/download/' . $filename,
                    'expires_at' => now()->addHours(24)->toISOString()
                ]
            ], 200);

        } catch (\Exception $e) {
            ErrorLog::logException($e, $request->user()->id);
            
            return response()->json([
                'success' => false,
                'message' => 'Failed to export logs',
                'error' => $e->getMessage()
            ], 500);
        }
    }
}