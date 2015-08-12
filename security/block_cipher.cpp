
#include "block_cipher.h"

namespace eja
{
	void block_cipher::set_key(const byte* key, const size_t key_size)
	{
		assert(key && (key_size == 16) || (key_size == 24) || (key_size == 32));

		m_key.Assign(key, key_size);
	}
}
