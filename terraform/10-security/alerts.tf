# ------------------------------------------------------------ telling a person
#
# Two things need someone and would otherwise only sit in the console: a finding
# the agent could not call benign, and a message that used up its three receives.
# Email subscriptions stay pending until the link AWS sends is clicked.
#
# No encryption on the topic: the AWS-managed SNS key's policy cannot be used by
# EventBridge or CloudWatch, and a customer-managed key costs more than this whole
# stage. So the emails carry the verdict and the finding's title, not its evidence.

resource "aws_sns_topic" "alerts" {
  name = "hubtriage-alerts"
}

resource "aws_sns_topic_subscription" "email" {
  topic_arn = aws_sns_topic.alerts.arn
  protocol  = "email"
  endpoint  = var.alert_email
}

# hubtriage_verdict is set only by the agent's write-back. Requiring NOTIFIED means
# GuardDuty updating a finding emails again, but a person closing it stops the email.
resource "aws_cloudwatch_event_rule" "needs_a_person" {
  name        = "hubtriage-needs-a-person"
  description = "Findings the agent called a true positive or could not settle."
  event_pattern = jsonencode({
    source        = ["aws.securityhub"]
    "detail-type" = ["Security Hub Findings - Imported"]
    detail = {
      findings = {
        RecordState       = ["ACTIVE"]
        Workflow          = { Status = ["NOTIFIED"] }
        UserDefinedFields = { hubtriage_verdict = ["true_positive", "needs_human"] }
      }
    }
  })
}

resource "aws_cloudwatch_event_target" "needs_a_person" {
  rule = aws_cloudwatch_event_rule.needs_a_person.name
  arn  = aws_sns_topic.alerts.arn
  input_transformer {
    input_paths = {
      verdict  = "$.detail.findings[0].UserDefinedFields.hubtriage_verdict"
      severity = "$.detail.findings[0].Severity.Label"
      title    = "$.detail.findings[0].Title"
      account  = "$.detail.findings[0].AwsAccountId"
      id       = "$.detail.findings[0].Id"
    }
    input_template = "\"hubtriage: <verdict> (<severity>) in account <account>\\n\\n<title>\\n\\nFinding: <id>\""
  }
}

# Visible, not sent: SQS does not count a message moved by a redrive as sent.
resource "aws_cloudwatch_metric_alarm" "dead_letters" {
  alarm_name          = "hubtriage-dead-letters"
  alarm_description   = "A finding's message used up its receives and is parked untriaged."
  namespace           = "AWS/SQS"
  metric_name         = "ApproximateNumberOfMessagesVisible"
  dimensions          = { QueueName = aws_sqs_queue.dlq.name }
  statistic           = "Maximum"
  period              = 300
  evaluation_periods  = 1
  comparison_operator = "GreaterThanThreshold"
  threshold           = 0
  treat_missing_data  = "notBreaching"
  alarm_actions       = [aws_sns_topic.alerts.arn]
}

data "aws_iam_policy_document" "alerts" {
  statement {
    sid       = "FromTheRule"
    actions   = ["sns:Publish"]
    resources = [aws_sns_topic.alerts.arn]
    principals {
      type        = "Service"
      identifiers = ["events.amazonaws.com"]
    }
    condition {
      test     = "ArnEquals"
      variable = "aws:SourceArn"
      values   = [aws_cloudwatch_event_rule.needs_a_person.arn]
    }
  }
  statement {
    sid       = "FromTheAlarm"
    actions   = ["sns:Publish"]
    resources = [aws_sns_topic.alerts.arn]
    principals {
      type        = "Service"
      identifiers = ["cloudwatch.amazonaws.com"]
    }
    condition {
      test     = "ArnEquals"
      variable = "aws:SourceArn"
      values   = [aws_cloudwatch_metric_alarm.dead_letters.arn]
    }
  }
}

resource "aws_sns_topic_policy" "alerts" {
  arn    = aws_sns_topic.alerts.arn
  policy = data.aws_iam_policy_document.alerts.json
}
