# frozen_string_literal: true

desc "Anonymize all existing IP addresses in the database"
task "anonymize:existing_ips" => :environment do
  puts "Starting IP anonymization task…"

  unless SiteSetting.discourse_ip_anonymizer_enabled
    puts "ERROR: discourse_ip_anonymizer_enabled is disabled"
    exit 1
  end

  if SiteSetting.discourse_ip_anonymizer_secret_key.blank?
    puts "ERROR: discourse_ip_anonymizer_secret_key is not configured"
    exit 1
  end

  connection = ActiveRecord::Base.connection
  quote      = ->(value) { connection.quote(value) }
  batch_size = 1_000

  TABLES_WITH_ID ||= [
    { table: "users", column: "ip_address" },
    { table: "users", column: "registration_ip_address" },
    { table: "user_auth_tokens", column: "client_ip" },
    { table: "user_auth_token_logs", column: "client_ip" },
    { table: "incoming_links", column: "ip_address" },
    { table: "search_logs", column: "ip_address" },
    { table: "topic_link_clicks", column: "ip_address" },
    { table: "user_profile_views", column: "ip_address" },
    { table: "user_histories", column: "ip_address" },
    { table: "user_ip_address_histories", column: "ip_address" },
    { table: "screened_emails", column: "ip_address" },
    { table: "screened_urls", column: "ip_address" }
  ].freeze

  TABLES_WITHOUT_ID ||= [
    { table: "topic_views", column: "ip_address" }
  ].freeze

  total_rows_updated = 0

  # ------------------------------------------------------------
  # Tables with primary key (safe cursor-based batching)
  # ------------------------------------------------------------
  TABLES_WITH_ID.each do |config|
    table  = config[:table]
    column = config[:column]

    puts "\nProcessing #{table}.#{column}"

    last_id = 0

    loop do
      rows = connection.exec_query(<<~SQL)
        SELECT id, #{column}
        FROM #{table}
        WHERE #{column} IS NOT NULL
          AND id > #{last_id}
        ORDER BY id
        LIMIT #{batch_size}
      SQL

      break if rows.empty?

      case_fragments = []

      rows.each do |row|
        original_ip = row[column].to_s
        anonymized  = ::DiscourseIpAnonymizer.anonymize_ip_address(original_ip)
        next if anonymized.blank?

        case_fragments << "WHEN #{row['id']} THEN #{quote.call(anonymized)}::inet"
      end

      if case_fragments.any?
        ids = rows.map { |r| r["id"] }.join(",")

        affected = connection.exec_update(<<~SQL)
          UPDATE #{table}
          SET #{column} = CASE id
            #{case_fragments.join("\n")}
          END
          WHERE id IN (#{ids})
        SQL

        total_rows_updated += affected
      end

      last_id = rows.last["id"]
      print "."
    end

    puts "\nFinished #{table}.#{column}"
  end

  # ------------------------------------------------------------
  # Tables without primary key (distinct-IP update)
  # ------------------------------------------------------------
  TABLES_WITHOUT_ID.each do |config|
    table  = config[:table]
    column = config[:column]

    puts "\nProcessing #{table}.#{column}"

    distinct_ips = connection.exec_query(<<~SQL)
      SELECT DISTINCT #{column}
      FROM #{table}
      WHERE #{column} IS NOT NULL
    SQL

    distinct_ips.each_with_index do |row, index|
      original_ip = row[column].to_s
      anonymized  = ::DiscourseIpAnonymizer.anonymize_ip_address(original_ip)
      next if anonymized.blank?

      affected = connection.exec_update(<<~SQL)
        UPDATE #{table}
        SET #{column} = #{quote.call(anonymized)}::inet
        WHERE #{column} = #{quote.call(original_ip)}
      SQL

      total_rows_updated += affected
      print "." if (index + 1) % 50 == 0
    end

    puts "\nFinished #{table}.#{column}"
  end

  puts "\n✅ IP anonymization completed"
  puts "Total rows updated: #{total_rows_updated}"
end