"""Mapping from AgentDojo tool names to Portcullis ExposureLabel.

This is the intellectual core of the benchmark adapter. Each AgentDojo tool
is classified into one of three exposure legs:

  PrivateData     — reads sensitive user data (emails, bank, files, contacts)
  UntrustedContent — ingests external/attacker-controllable content (web, downloads)
  ExfilVector      — outbound channel that could leak data (send, post, transfer)

Tools not in this map default to None (neutral, always allowed).
Unknown tools also default to None (fail-open for utility).

The mapping is derived from AgentDojo's 4 task suites:
  - workspace (email, calendar, cloud drive, contacts)
  - workspace_plus (workspace + web tools)
  - travel (hotels, flights, restaurants, cars, web)
  - banking (accounts, transactions)
  - slack (channels, messages)
"""

from __future__ import annotations

from typing import Optional

# Avoid circular import — use a string sentinel, resolved at import time
# by exposure.py which converts to ExposureLabel enum values.
# Actually, let's just import directly since this is a leaf module.
from enum import Enum, auto


class ExposureLabel(Enum):
    PrivateData = auto()
    UntrustedContent = auto()
    ExfilVector = auto()


# Re-export for exposure.py
# NOTE: exposure.py defines its own ExposureLabel; this module uses the
# same enum to keep the map self-contained. exposure.py imports from here.

TOOL_MAP: dict[str, Optional[ExposureLabel]] = {
    # =========================================================================
    # Banking suite
    # =========================================================================
    "get_balance": ExposureLabel.PrivateData,
    "get_iban": ExposureLabel.PrivateData,
    "get_most_recent_transactions": ExposureLabel.PrivateData,
    "get_scheduled_transactions": ExposureLabel.PrivateData,
    "send_money": ExposureLabel.ExfilVector,
    "schedule_transaction": ExposureLabel.ExfilVector,
    "update_scheduled_transaction": None,  # modifying existing, not exfil
    "read_file": ExposureLabel.PrivateData,
    "get_user_info": ExposureLabel.PrivateData,
    "update_password": None,
    "update_user_info": None,
    # =========================================================================
    # Email (workspace + workspace_plus)
    # =========================================================================
    "get_unread_emails": ExposureLabel.PrivateData,
    "get_received_emails": ExposureLabel.PrivateData,
    "get_sent_emails": ExposureLabel.PrivateData,
    "get_draft_emails": ExposureLabel.PrivateData,
    "search_emails": ExposureLabel.PrivateData,
    "send_email": ExposureLabel.ExfilVector,
    "delete_email": None,
    "search_contacts_by_name": ExposureLabel.PrivateData,
    "search_contacts_by_email": ExposureLabel.PrivateData,
    # =========================================================================
    # Slack suite
    # =========================================================================
    "get_channels": ExposureLabel.PrivateData,
    "get_users_in_channel": ExposureLabel.PrivateData,
    "read_channel_messages": ExposureLabel.PrivateData,
    "read_inbox": ExposureLabel.PrivateData,
    "send_direct_message": ExposureLabel.ExfilVector,
    "send_channel_message": ExposureLabel.ExfilVector,
    "invite_user_to_slack": ExposureLabel.ExfilVector,
    "remove_user_from_slack": ExposureLabel.ExfilVector,
    "add_user_to_channel": None,
    # =========================================================================
    # Cloud drive (workspace)
    # =========================================================================
    "get_file_by_id": ExposureLabel.PrivateData,
    "list_files": ExposureLabel.PrivateData,
    "search_files": ExposureLabel.PrivateData,
    "search_files_by_filename": ExposureLabel.PrivateData,
    "create_file": ExposureLabel.ExfilVector,
    "delete_file": None,
    "share_file": ExposureLabel.ExfilVector,
    "append_to_file": None,
    # =========================================================================
    # Web (workspace_plus, travel)
    # =========================================================================
    "get_webpage": ExposureLabel.UntrustedContent,
    "post_webpage": ExposureLabel.ExfilVector,
    "download_file": ExposureLabel.UntrustedContent,
    # =========================================================================
    # Calendar (workspace)
    # =========================================================================
    "get_day_calendar_events": ExposureLabel.PrivateData,
    "create_calendar_event": None,
    "search_calendar_events": ExposureLabel.PrivateData,
    "cancel_calendar_event": None,
    "update_calendar_event": None,
    "reschedule_calendar_event": None,
    "add_calendar_event_participants": ExposureLabel.ExfilVector,  # emails new participants
    "get_current_day": None,
    # =========================================================================
    # Travel suite
    # =========================================================================
    "get_all_hotels_in_city": ExposureLabel.PrivateData,
    "get_hotels_prices": ExposureLabel.PrivateData,
    "get_hotels_address": ExposureLabel.PrivateData,
    "get_rating_reviews_for_hotels": ExposureLabel.UntrustedContent,  # reviews = untrusted
    "get_hotel_reviews": ExposureLabel.UntrustedContent,
    "reserve_hotel": ExposureLabel.ExfilVector,  # consequential financial action
    "get_all_restaurants_in_city": ExposureLabel.PrivateData,
    "get_cuisine_type_for_restaurants": ExposureLabel.PrivateData,
    "get_rating_reviews_for_restaurants": ExposureLabel.UntrustedContent,
    "get_dietary_restrictions_for_all_restaurants": ExposureLabel.PrivateData,
    "get_restaurants_address": ExposureLabel.PrivateData,
    "get_contact_information_for_restaurants": ExposureLabel.PrivateData,
    "get_price_for_restaurants": ExposureLabel.PrivateData,
    "check_restaurant_opening_hours": ExposureLabel.PrivateData,
    "reserve_restaurant": ExposureLabel.ExfilVector,
    "get_all_car_rental_companies_in_city": ExposureLabel.PrivateData,
    "get_car_types_available": ExposureLabel.PrivateData,
    "get_car_fuel_options": ExposureLabel.PrivateData,
    "get_car_price_per_day": ExposureLabel.PrivateData,
    "reserve_car": ExposureLabel.ExfilVector,
    "reserve_car_rental": ExposureLabel.ExfilVector,
    "get_car_rental_address": ExposureLabel.PrivateData,
    "get_rating_reviews_for_car_rental": ExposureLabel.UntrustedContent,  # reviews = untrusted
    "get_flight_information": ExposureLabel.PrivateData,
    "purchase_flight": ExposureLabel.ExfilVector,
    "get_user_information": ExposureLabel.PrivateData,
    "verify_user_information": ExposureLabel.PrivateData,
    "get_budget_for_trip": ExposureLabel.PrivateData,
    "update_budget_for_trip": None,
    "get_closest_airport": ExposureLabel.PrivateData,
    "book_excursion": ExposureLabel.ExfilVector,
    "get_all_excursions": ExposureLabel.PrivateData,
    "cancel_reservation": None,
}
