import unittest
from unittest.mock import patch, MagicMock
import pandas as pd

class TestWithdrawCash(unittest.TestCase):
    def test_withdraw_cash_successful(self, mock_st):
        # Setup mock inputs
        mock_st.number_input.side_effect = [12345, 100.00]  # valid account number and withdrawal amount
        mock_st.button.return_value = True

        # Mocking the account and transaction DataFrames
        accounts_df = pd.DataFrame({
            'Balance': [200.00]
        }, index=[12345])

        transactions_df = pd.DataFrame(columns=['Date', 'Type', 'From', 'To', 'Amount'])

        with patch('your_module.accounts_df', accounts_df), \
             patch('your_module.transactions_df', transactions_df), \
             patch('your_module.save_data') as mock_save_data, \
             patch('your_module.logging') as mock_logging:
            # Run the function
            your_module.withdraw_cash()

            # Assert balance updated
            self.assertEqual(accounts_df.at[12345, 'Balance'], 100.00)
            
            # Assert transaction recorded
            self.assertEqual(transactions_df.iloc[0]['Amount'], 100.00)
            self.assertEqual(transactions_df.iloc[0]['Type'], 'Withdrawal')

            # Assert data saved and success message
            self.assertEqual(mock_save_data.call_count, 2)  # called twice, for accounts and transactions
            mock_st.success.assert_called_once_with('Withdrawal successful!')
            mock_logging.info.assert_called_once()

    @patch('your_module.st')
    def test_withdraw_cash_insufficient_funds(self, mock_st):
        # Setup mock inputs
        mock_st.number_input.side_effect = [12345, 300.00]  # valid account number but insufficient amount
        mock_st.button.return_value = True

        # Mocking the account DataFrame
        accounts_df = pd.DataFrame({
            'Balance': [200.00]
        }, index=[12345])

        with patch('your_module.accounts_df', accounts_df):
            # Run the function
            your_module.withdraw_cash()

            # Check no changes in the balance and error message
            self.assertEqual(accounts_df.at[12345, 'Balance'], 200.00)
            mock_st.error.assert_called_once_with('Insufficient funds!')

if __name__ == '__main__':
    unittest.main()
