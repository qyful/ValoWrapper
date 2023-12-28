import valowrapper

api = valowrapper.API("HDEV-564c3d5d-1ab6-46bd-82a9-4bac833ec23c", retry_count=2, wait_on_rate_limit=False)

print(api.get_account_details("Waffle", "oli"))