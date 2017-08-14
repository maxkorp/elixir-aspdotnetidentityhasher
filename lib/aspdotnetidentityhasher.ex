defmodule Aspdotnetidentityhasher do
  def hash_password(password) do
    with salt = :crypto.strong_rand_bytes(16),
         {:ok, passhash} = do_hash(password, salt),
         output = <<0>> <> salt <> passhash,
    do: Base.encode64(output)
  end

  def validate_password(password, hashed) do
    with {:ok, <<_, salt::128, old_bytes::256>>} = Base.decode64(hashed),
         {:ok, new_bytes} = do_hash(password, <<salt:: 128>>),
    do: <<old_bytes::256>> == new_bytes
  end

  defp do_hash(password, salt) do
    :pbkdf2.pbkdf2(:sha, password, salt, 1000, 32)
  end
end
