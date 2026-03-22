// Donna - Continuous AI Pentesting Platform
//
// This program is free software: you can redistribute it and/or modify
// it under the terms of the GNU Affero General Public License version 3
// as published by the Free Software Foundation.

/**
 * Temporal event type enum mapping.
 * The Temporal SDK can return numeric enum values instead of string names.
 * This maps them to human-readable names.
 */

export const EVENT_TYPE_MAP: Record<number, string> = {
  0: 'Unspecified',
  1: 'Workflow Execution Started',
  2: 'Workflow Execution Completed',
  3: 'Workflow Execution Failed',
  4: 'Workflow Execution Timed Out',
  5: 'Workflow Task Scheduled',
  6: 'Workflow Task Started',
  7: 'Workflow Task Completed',
  8: 'Workflow Task Timed Out',
  9: 'Workflow Task Failed',
  10: 'Activity Task Scheduled',
  11: 'Activity Task Started',
  12: 'Activity Task Completed',
  13: 'Activity Task Failed',
  14: 'Activity Task Timed Out',
  15: 'Activity Task Cancel Requested',
  16: 'Activity Task Canceled',
  17: 'Timer Started',
  18: 'Timer Fired',
  19: 'Timer Canceled',
  20: 'Workflow Execution Cancel Requested',
  21: 'Workflow Execution Canceled',
  22: 'Request Cancel External Workflow Execution Initiated',
  23: 'Request Cancel External Workflow Execution Failed',
  24: 'External Workflow Execution Cancel Requested',
  25: 'Marker Recorded',
  26: 'Workflow Execution Signaled',
  27: 'Workflow Execution Terminated',
  28: 'Workflow Execution Continued As New',
  29: 'Start Child Workflow Execution Initiated',
  30: 'Start Child Workflow Execution Failed',
  31: 'Child Workflow Execution Started',
  32: 'Child Workflow Execution Completed',
  33: 'Child Workflow Execution Failed',
  34: 'Child Workflow Execution Canceled',
  35: 'Child Workflow Execution Timed Out',
  36: 'Child Workflow Execution Terminated',
  37: 'Signal External Workflow Execution Initiated',
  38: 'Signal External Workflow Execution Failed',
  39: 'External Workflow Execution Signaled',
  40: 'Upsert Workflow Search Attributes',
};

/**
 * Convert an event type value (numeric or string) to a human-readable name.
 */
export function resolveEventTypeName(eventType: unknown): string {
  // If it's a number, look up in the map
  if (typeof eventType === 'number') {
    return EVENT_TYPE_MAP[eventType] || `Event Type ${eventType}`;
  }

  const str = String(eventType);

  // If it's already a nice name
  if (!str.includes('_') && !str.match(/^\d+$/)) {
    return str;
  }

  // If it's a numeric string
  if (str.match(/^\d+$/)) {
    const num = parseInt(str, 10);
    return EVENT_TYPE_MAP[num] || `Event Type ${str}`;
  }

  // If it's an enum string like EVENT_TYPE_WORKFLOW_EXECUTION_STARTED
  return str
    .replace('EVENT_TYPE_', '')
    .replace(/_/g, ' ')
    .toLowerCase()
    .replace(/\b\w/g, (c: string) => c.toUpperCase());
}

/**
 * Get the CSS category class for an event type.
 */
export function getEventCategory(typeName: string): string {
  const t = typeName.toLowerCase();
  if (t.includes('started') || t.includes('initiated')) return 'start';
  if (t.includes('completed') || t.includes('succeeded')) return 'success';
  if (t.includes('failed') || t.includes('timed out') || t.includes('canceled') || t.includes('terminated')) return 'error';
  if (t.includes('scheduled') || t.includes('fired')) return 'scheduled';
  if (t.includes('activity')) return 'activity';
  return 'default';
}

/**
 * Extract meaningful details from an event's attributes.
 */
export function extractEventDetails(ev: any): Record<string, string> {
  const details: Record<string, string> = {};

  // WorkflowExecutionStarted
  if (ev.workflowExecutionStartedEventAttributes) {
    const attrs = ev.workflowExecutionStartedEventAttributes;
    if (attrs.workflowType?.name) details['Workflow Type'] = attrs.workflowType.name;
    if (attrs.taskQueue?.name) details['Task Queue'] = attrs.taskQueue.name;
    if (attrs.attempt) details['Attempt'] = String(attrs.attempt);
  }

  // ActivityTaskScheduled
  if (ev.activityTaskScheduledEventAttributes) {
    const attrs = ev.activityTaskScheduledEventAttributes;
    if (attrs.activityType?.name) details['Activity Type'] = attrs.activityType.name;
    if (attrs.taskQueue?.name) details['Task Queue'] = attrs.taskQueue.name;
    if (attrs.activityId) details['Activity ID'] = attrs.activityId;
  }

  // ActivityTaskStarted
  if (ev.activityTaskStartedEventAttributes) {
    const attrs = ev.activityTaskStartedEventAttributes;
    if (attrs.scheduledEventId) details['Scheduled Event'] = `#${attrs.scheduledEventId}`;
    if (attrs.attempt) details['Attempt'] = String(attrs.attempt);
  }

  // ActivityTaskCompleted
  if (ev.activityTaskCompletedEventAttributes) {
    const attrs = ev.activityTaskCompletedEventAttributes;
    if (attrs.scheduledEventId) details['Scheduled Event'] = `#${attrs.scheduledEventId}`;
    if (attrs.startedEventId) details['Started Event'] = `#${attrs.startedEventId}`;
  }

  // ActivityTaskFailed
  if (ev.activityTaskFailedEventAttributes) {
    const attrs = ev.activityTaskFailedEventAttributes;
    if (attrs.scheduledEventId) details['Scheduled Event'] = `#${attrs.scheduledEventId}`;
    if (attrs.failure?.message) details['Failure'] = attrs.failure.message;
  }

  // WorkflowTaskScheduled
  if (ev.workflowTaskScheduledEventAttributes) {
    const attrs = ev.workflowTaskScheduledEventAttributes;
    if (attrs.taskQueue?.name) details['Task Queue'] = attrs.taskQueue.name;
  }

  // WorkflowTaskCompleted
  if (ev.workflowTaskCompletedEventAttributes) {
    const attrs = ev.workflowTaskCompletedEventAttributes;
    if (attrs.scheduledEventId) details['Scheduled Event'] = `#${attrs.scheduledEventId}`;
  }

  // WorkflowExecutionCompleted
  if (ev.workflowExecutionCompletedEventAttributes) {
    details['Status'] = 'Completed';
  }

  // WorkflowExecutionFailed
  if (ev.workflowExecutionFailedEventAttributes) {
    const attrs = ev.workflowExecutionFailedEventAttributes;
    if (attrs.failure?.message) details['Failure'] = attrs.failure.message;
  }

  // TimerStarted
  if (ev.timerStartedEventAttributes) {
    const attrs = ev.timerStartedEventAttributes;
    if (attrs.timerId) details['Timer ID'] = attrs.timerId;
  }

  // TimerFired
  if (ev.timerFiredEventAttributes) {
    const attrs = ev.timerFiredEventAttributes;
    if (attrs.timerId) details['Timer ID'] = attrs.timerId;
    if (attrs.startedEventId) details['Started Event'] = `#${attrs.startedEventId}`;
  }

  return details;
}
