"""A minimal, read-only local web viewer for saved nodezero-lite reports.

This package cannot start a scan, change an authorization, or touch a
target — it only renders JSON report files that `nodezero run` already
wrote to disk. Treat it as a nicer way to read a report you already have,
not a second way to run one.
"""
