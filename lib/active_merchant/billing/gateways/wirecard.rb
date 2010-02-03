require 'base64'

module ActiveMerchant #:nodoc:
  module Billing #:nodoc:
    class WirecardGateway < Gateway
      # Test server location.
      TEST_URL = 'https://c3-test.wirecard.com/secure/ssl-gateway'

      # Live server location.
      LIVE_URL = 'https://c3.wirecard.com/secure/ssl-gateway'

      # The Namespaces are not really needed, because it just tells the System,
      # that there's actually no namespace used.
      # It's just specified here for completeness.
      ENVELOPE_NAMESPACES = {
        'xmlns:xsi' => 'http://www.w3.org/1999/XMLSchema-instance',
        'xsi:noNamespaceSchemaLocation' => 'wirecard.xsd'
      }

      PERMITTED_TRANSACTIONS = %w[ AUTHORIZATION CAPTURE_AUTHORIZATION PURCHASE ]

      RETURN_CODES = %w[ ACK NOK ]

      # Wirecard only allows phone numbers with a format like this:
      #   +xxx(yyy)zzz-zzzz-ppp
      # where:
      #   xxx = Country code
      #   yyy = Area or city code
      #   zzz-zzzz = Local number
      #   ppp = PBX extension
      # For example, a typical U.S. or Canadian number would be "+1(202)555-1234-739"
      # indicating PBX extension 739 at phone number 5551234 within area code
      # 202 (country code 1).
      VALID_PHONE_FORMAT = /\+\d{1,3}(\(?\d{3}\)?)?\d{3}-\d{4}-\d{3}/

      # The countries the gateway supports merchants from as 2 digit ISO country codes.
      # TODO: Check supported countries
      self.supported_countries = ['DE']

      # Wirecard supports all major credit and debit cards:
      # Visa, Mastercard, American Express, Diners Club,
      # JCB, Switch, VISA Carte Bancaire, Visa Electron and UATP cards.
      # They also support the latest anti-fraud systems such as Verified by Visa
      # or Master Secure Code.
      self.supported_cardtypes = [
        :visa, :master, :american_express, :diners_club, :jcb, :switch
      ]

      # The homepage URL of the gateway.
      self.homepage_url = 'http://www.wirecard.com'

      # The name of the gateway.
      self.display_name = 'Wirecard'

      # The currency should normally be EURO.
      self.default_currency = 'EUR'

      # 100 is 1.00 Euro
      self.money_format = :cents

      def initialize(options = {})
        # Verify that username and password are supplied.
        requires!(options, :login, :password)
        # Wirecard also requires a BusinessCaseSignature in the XML request.
        requires!(options, :signature)
        @options = options
        super
      end

      # Should run against the test servers or not?
      def test?
        @options[:test] || super
      end

      # 6.5 Authorization.
      # During a card authorization, the transaction information is sent to Wirecard,
      # which in turn sends the information to the cardholder's issuing financial institution.
      # An Authorization is not a guarantee of payment. It only confirms that
      # the card exists and that funds are available at the time of Authorization
      # to cover a purchase amount. The funds are not credited at this time but
      # the Authorization reduces the available credit limit for that card, so
      # in a sense the funds are reserved for the purchase.
      def authorize(money, credit_card, options = {})
        prepare_options_hash(options)
        @options[:credit_card] = credit_card
        request = build_request(:authorization, money, @options)
        commit(request)
      end

      # 6.6 Authorization Check.
      # Wirecard also supports the transaction type FNC_CC_AUTHORIZATION_CHECK.
      # In addition to the default Luhn Check, an algorithm which verifies a
      # credit card number against its check digit, the Authorization Check
      # allows merchants to validate credit cards used in online transactions
      # in real-time against the database of the card issuing bank.
      # This transaction request type cannot be sent with the transaction
      # mode type initial available with recurring transactions and installment transactions.

      # The Authorization Check is almost identical to the Authorization request
      # described in the previous section. The only thing that sets it apart
      # from a standard Authorization is that the amount specified in this
      # check request is not reserved for a later Capture Authorization but
      # automatically reversed. As the name indicates, an Authorization Check
      # is a verification of the credit card only and does not replace the
      # standard Authorization request.
      def check(money, credit_card, options = {})
        prepare_options_hash(options)
        @options[:credit_card] = credit_card
        request = build_request(:authorization_check, money, @options)
        commit(request)
      end

      # 6.7 Capture Authorization.
      # Wirecard supports two types of Capture Authorization, one which is
      # related to a previous authorization of the captured amount
      # (i.e. a capture request message which contains a reference to the initial
      # Authorization request), and one which has no connection to a previous
      # authorization and is therefore sent without reference in the XML code.

      # A Capture Authorization request must include a valid GuWID referencing
      # the previous Authorization request. The transaction amount which is to
      # be captured must be identical to the amount authorized, if both transaction
      # types are processed in real-time.
      # The GuWID is references in this method as the second parameter.
      def capture(money, authorization, options = {})
        prepare_options_hash(options)
        @options[:authorization] = authorization
        request = build_request(:capture_authorization, money, @options)
        commit(request)
      end

      # 6.8 Purchase.
      # A purchase request both authorizes and settles the requested amount
      # against the card indicated. Through authorizing, the Transaction request
      # confirms that the card exists and that funds are available at the time
      # of Authorization to cover the transaction amount. The funds are not
      # credited at this time but the Authorization reduces the available credit
      # limit for that card, so in a sense the funds are “reserved” for the purchase.
      # Through settlement, the purchase request completes the transaction -
      # the issuing financial institution credits the merchant's bank account
      # with the funds for the purchase and updates the cardholder's statement.
      def purchase(money, credit_card, options = {})
        prepare_options_hash(options)
        @options[:credit_card] = credit_card
        request = build_request(:purchase, money, @options)
        commit(request)
      end

      private

        def prepare_options_hash(options)
          @options.update(options)
          setup_address_hash!(options)
        end

        # Create all address hash key value pairs so that it still works if
        # only provided with one or two of them.
        # Also include Email in address Hash from options Hash.
        def setup_address_hash!(options)
          options[:billing_address]  = options[:billing_address] || options[:address] || {}
          options[:shipping_address] = options[:shipping_address] || {}
          options[:billing_address][:email] = options[:email] if options[:email]
        end

        # Contact WireCard, make the XML request, and parse the reply into a Response object.
        def commit(request)
          headers = {
            'Content-Type'  => 'text/xml',
            'Authorization' => encoded_credentials
          }

          response = parse(ssl_post(test? ? TEST_URL : LIVE_URL, request, headers))
          # Pending Status also means Acknowledged (as stated in their specification).
          success = response[:FunctionResult] == "ACK" || response[:FunctionResult] == "PENDING"
          message = response[:Message]
          authorization = (success && @options[:action] == :authorization) ? response[:GuWID] : nil

          Response.new(
            success, message, response,
            :test          => test?,
            :authorization => authorization,
            :avs_result    => { :code => response[:avsCode] },
            :cvv_result    => response[:cvCode]
          )
        end

        # Generates the complete XML message, that gets sent to the gateway.
        def build_request(action, money, options = {})
          xml = Builder::XmlMarkup.new :indent => 2
          xml.instruct!
          xml.tag! 'WIRECARD_BXML' do
            xml.tag! 'W_REQUEST' do
              xml.tag! 'W_JOB' do
                # TODO: OPTIONAL, check what value needs to be insert here.
                xml.tag! 'JobID', 'test dummy data'
                # UserID for this transaction.
                xml.tag! 'BusinessCaseSignature', options[:signature] || options[:login]
                # Create the whole rest of the message.
                add_transaction_data(xml, action, money, options)
              end
            end
          end
          xml.target!
        end

        # Includes the whole transaction data:
        #   +payment_informations+
        #   +credit_card+
        #   +address+
        def add_transaction_data(xml, action, money, options = {})
          # FIXME: require order_id instead of auto-generating it if not supplied
          options[:order_id] ||= generate_unique_id

          # Supported Wirecard transaction types:
          #   :preauthorization
          #   :capture_preauthorization
          #   :preauthorization_supplement
          #   :capture_preauthorization_supplement
          #   :authorization
          #   :authorization_check
          #   :capture_authorization
          #   :purchase
          #   :notification
          #   :bookback
          #   :reversal
          #   :original_credits
          #   :query
          #   :refund
          options[:action] = action
          transaction_type = action.to_s.upcase

          xml.tag! "FNC_CC_#{transaction_type}" do
            # This ID is reserved for merchant system data and can be used for
            # tracking purposes. Although it is optional meaning that it does
            # not have to contain data, the element itself (<FunctionID> </FunctionID>)
            # must still be provided in the XML request.
            # Omitting the element will result in a response error.
            xml.tag! 'FunctionID', options[:description] || 'No FunctionID set'

            xml.tag! 'CC_TRANSACTION' do
              xml.tag! 'TransactionID', options[:order_id]

              if [:authorization, :purchase, :authorization_check].include?(action)
                add_payment_informations(xml, money, options)
                add_credit_card(xml, options[:credit_card])
                add_billing_address(xml, options[:billing_address])
              elsif action == :capture_authorization
                xml.tag! 'GuWID', options[:authorization] if options[:authorization]
              end

            end
          end
        end

        # Includes the payment (amount, currency, options) to the transaction XML.
        def add_payment_informations(xml, money, options)
          xml.tag! 'Amount', amount(money)
          xml.tag! 'Currency', options[:currency] || currency(money)
          # A recurring transaction describes a payment where the cardholder's
          # account is periodically charged for a repeated delivery and use of
          # a product or service (subscription, membership fee, etc.) over time.
          # A recurring transaction consists of an initial request
          # (which is identical in form and content to a single request) and
          # one or several repeated transaction request messages.
          # The "+Initial+" request message (which in most cases is an Authorization)
          # contains all relevant card and cardholder data, while the subsequent
          # "+Repeated+" message (which can be another Authorization, or a Capture or a Purchase)
          # simply references an identifier (the Global Unique Wirecard ID)
          # which is returned with the response message to the initial request.

          # This is the ISO 3166-1 code of the country where the transaction takes place.
          # It is mandatory if the type of transaction is ‘Single’ or ‘Initial’.
          xml.tag! 'CountryCode', options[:billing_address][:country]

          # Recurring transaction types:
          #   :purchase
          #   :authorization
          #   :preauthorization
          xml.tag! 'RECURRING_TRANSACTION' do
            # Recurring options:
            #   +'Initial'+
            #   +'Single'+
            #   +'Repeated'+

            # NOTE: If the payment card data of a customer has changed, all
            # data must be re-submitted in form of an 'initial' transaction.
            # The system will generate a new reference GuWID which must be used
            # for all subsequent transactions by this cardholder.
            xml.tag! 'Type', options[:recurring] || 'Single'
          end
        end

        # Includes the credit card data to the transaction XML.
        def add_credit_card(xml, credit_card)
          raise "Credit card must be supplied!" if credit_card.nil?
          xml.tag! 'CREDIT_CARD_DATA' do
            xml.tag! 'CreditCardNumber', credit_card.number
            xml.tag! 'CVC2', credit_card.verification_value
            xml.tag! 'ExpirationYear', credit_card.year
            xml.tag! 'ExpirationMonth', format(credit_card.month, :two_digits)
            xml.tag! 'CardHolderName', [credit_card.first_name, credit_card.last_name].join(' ')
          end
        end

        # Includes the IP address of the customer to the transaction XML.
        def add_customer_data(xml, options)
          return unless options[:ip]
          xml.tag! 'CONTACT_DATA' do
            xml.tag! 'IPAddress', options[:ip]
          end
        end

        # Includes the address to the transaction XML.
        def add_billing_address(xml, address)
          return if address.nil?
          xml.tag! 'CORPTRUSTCENTER_DATA' do
            xml.tag! 'ADDRESS' do
              xml.tag! 'Address1', address[:address1]
              xml.tag! 'Address2', address[:address2] if address[:address2]
              xml.tag! 'City', address[:city]
              xml.tag! 'ZipCode', address[:zip]

              if address[:state] =~ /[A-Za-z]{2}/ && address[:country] =~ /^(us|ca)$/i
                xml.tag! 'State', address[:state].upcase
              end

              xml.tag! 'Country', address[:country]
              xml.tag! 'Phone', address[:phone] if address[:phone] =~ VALID_PHONE_FORMAT
              xml.tag! 'Email', address[:email]
            end
          end
        end


        # Read the XML message from the gateway and check if it was successful,
        # and also extract required return values from the response.
        def parse(xml)
          basepath = '/WIRECARD_BXML/W_RESPONSE'
          response = {}

          xml = REXML::Document.new(xml)
          if root = REXML::XPath.first(xml, "#{basepath}/W_JOB")
            parse_response(response, root)
          elsif root = REXML::XPath.first(xml, "//ERROR")
            parse_error(response, root)
          else
            response[:Message] = "No valid XML response message received. \
                                  Probably wrong credentials supplied with HTTP header."
          end

          response
        end

        # Parse the <ProcessingStatus> Element which containts all important
        # informations.
        def parse_response(response, root)
          status = nil
          # Get the root element for this Transaction
          root.elements.to_a.each do |node|
            if node.name =~ /FNC_CC_/
              status = REXML::XPath.first(node, "CC_TRANSACTION/PROCESSING_STATUS")
            end
          end
          message = ""
          if status
            if info = status.elements['Info']
              message << info.text
            end
            # Get basic response information.
            status.elements.to_a.each do |node|
              response[node.name.to_sym] = (node.text || '').strip
            end
          end
          parse_error(root, message)
          response[:Message] = message
        end

        # Parse a generic error response from the gateway.
        def parse_error(root, message = "")
          # Get errors if available and append them to the message.
          errors = errors_to_string(root)
          unless errors.strip.blank?
            message << ' - ' unless message.strip.blank?
            message << errors
          end
          message
        end

        # Parses all <ERROR> elements in the response and converts the information
        # to a single string.
        def errors_to_string(root)
          # Get context error messages (can be 0..*)
          errors = []
          REXML::XPath.each(root, "//ERROR") do |error_elem|
            error = {}
            error[:Advice] = []
            error[:Message] = error_elem.elements['Message'].text
            error_elem.elements.each('Advice') do |advice|
              error[:Advice] << advice.text
            end
            errors << error
          end
          # Convert all messages to a single string.
          string = ''
          errors.each do |error|
            string << error[:Message]
            error[:Advice].each_with_index do |advice, index|
              string << ' (' if index == 0
              string << "#{index+1}. #{advice}"
              string << ' and ' if index < error[:Advice].size - 1
              string << ')' if index == error[:Advice].size - 1
            end
          end
          string
        end

        # Encode login and password in Base64 to supply as HTTP header for
        # HTTP basic authentication.
        def encoded_credentials
          credentials = [@options[:login], @options[:password]].join(':')
          "Basic " << Base64.encode64(credentials).strip
        end

    end
  end
end
