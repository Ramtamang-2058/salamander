# admin/exports.py - Data export functionality
import csv
import json
from io import StringIO
from flask import Response, make_response
from openpyxl import Workbook
from openpyxl.utils.dataframe import dataframe_to_rows
import pandas as pd


class DataExporter:
    @staticmethod
    def export_users_csv(users):
        """Export users to CSV"""
        output = StringIO()
        writer = csv.writer(output)

        # Write header
        writer.writerow(['UID', 'Name', 'Email', 'Is Premium', 'Word Credits', 'Created At'])

        # Write data
        for user in users:
            writer.writerow([
                user.uid,
                user.name,
                user.email,
                user.is_premium,
                user.word_credits,
                user.created_at.strftime('%Y-%m-%d %H:%M:%S')
            ])

        output.seek(0)
        return Response(
            output.getvalue(),
            mimetype='text/csv',
            headers={'Content-Disposition': 'attachment; filename=users.csv'}
        )

    @staticmethod
    def export_payments_csv(payments):
        """Export payments to CSV"""
        output = StringIO()
        writer = csv.writer(output)

        # Write header
        writer.writerow(['ID', 'User ID', 'Plan', 'Amount', 'Status', 'Payment Method', 'Created At'])

        # Write data
        for payment in payments:
            writer.writerow([
                payment.id,
                payment.user_id,
                payment.plan,
                payment.amount,
                payment.status,
                payment.payment_method,
                payment.created_at.strftime('%Y-%m-%d %H:%M:%S')
            ])

        output.seek(0)
        return Response(
            output.getvalue(),
            mimetype='text/csv',
            headers={'Content-Disposition': 'attachment; filename=payments.csv'}
        )

    @staticmethod
    def export_to_excel(data, filename, sheet_name='Data'):
        """Export data to Excel"""
        df = pd.DataFrame(data)

        output = BytesIO()
        with pd.ExcelWriter(output, engine='openpyxl') as writer:
            df.to_excel(writer, sheet_name=sheet_name, index=False)

        output.seek(0)

        response = make_response(output.getvalue())
        response.headers['Content-Type'] = 'application/vnd.openxmlformats-officedocument.spreadsheetml.sheet'
        response.headers['Content-Disposition'] = f'attachment; filename={filename}.xlsx'

        return response