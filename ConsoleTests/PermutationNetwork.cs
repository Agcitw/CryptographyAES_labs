using CryptographyLabs;
using System;
using System.Collections.Generic;
using System.Linq;
using System.Text;
using System.Threading.Tasks;

namespace ConsoleTests
{
	class Swapper : PermutationNetwork
	{
		internal Swapper(byte[] permutation, int phase)
		{
			Masks.Add((permutation[0] == 1) ? 1ul << phase : 0);
		}
	}

	public class PermutationNetwork
	{
		// The list of masks for the final permutation
		public List<ulong> Masks { get; set; }

		protected PermutationNetwork()
		{
			Masks = new List<ulong>();
		}

		public PermutationNetwork(byte[] permutation) : this()
		{
			if (!CheckPermutation(permutation))
			{
				throw new ArgumentException("Invalid permutation to PermutationNetwork");
			}
			Initialize(permutation, 0);
		}

		private static bool CheckPermutation(byte[] permutation)
		{
			if (permutation.Length != 64)
			{
				return false;
			}
			long check = 0;
			for (int i = 0; i < 64; i++)
			{
#pragma warning disable CS0675 // Битовая операция или оператор, использовавшийся в операнде с расширением знака
				check |= 1 << i;
#pragma warning restore CS0675 // Битовая операция или оператор, использовавшийся в операнде с расширением знака
			}
			return check == -1;
		}

		private PermutationNetwork(byte[] permutation, int phaseParm) : this()
		{
			Initialize(permutation, phaseParm);
		}

		private void Initialize(byte[] permutation, int phase)
		{
			PermutationNetwork permutationNetworkEven;
			PermutationNetwork permutationNetworkOdd;
			int size = permutation.Length;
			int delta = 64 / size;
			ulong inputMask;
			ulong outputMask;

			// Get the wiring needed for our two inner networks
			byte[][] permutationsInner = GetInnerPermutations(permutation, delta, phase, out inputMask, out outputMask);

			// Recursively create those two inner networks
			if (size == 4)
			{
				// The recursion ends here by creating two swappers rather than normal permutation networks
				permutationNetworkEven = new Swapper(permutationsInner[0], phase);
				permutationNetworkOdd = new Swapper(permutationsInner[1], phase + delta);
			}
			else
			{
				// For larger sizes, the inner networks are standard permutation networks
				permutationNetworkEven = new PermutationNetwork(permutationsInner[0], phase);
				permutationNetworkOdd = new PermutationNetwork(permutationsInner[1], phase + delta);
			}

			// Extract the masks from our inner permutation networks into our list of masks
			ExtractMasks(permutationNetworkEven, permutationNetworkOdd, inputMask, outputMask);
		}

		private static byte[][] GetInnerPermutations(byte[] permutationOuter, int delta, int phase, out ulong inputMask, out ulong outputMask)
		{
			inputMask = 0;
			outputMask = 0;

			byte[][] permutationsInner = new byte[2][];
			int size = permutationOuter.Length;
			permutationsInner[0] = new byte[size / 2];
			permutationsInner[1] = new byte[size / 2];

			byte[] reversePermutation = GetReversePermutation(permutationOuter);

			// We map out cycles until we've covered all the inputs and their
			// connections to the outputs.  mappedToDest keeps track of which
			// inputs have been mapped and cMapped keeps track of the count of
			// mapped inputs.  When we end a cycle, if cMapped == size then
			// we're done.  If it's not, then we find an unmapped input and
			// map out the cycle starting from that input.
			bool[] mappedToDest = new bool[size];
			int cMapped = 0;

			// While there are cycles to map...
			while (cMapped < size)
			{
				bool fInput = true;
				byte network = 0;
				byte startPin;

				// Find the next unmapped input
				for (startPin = 0; startPin < size; startPin++)
				{
					if (!mappedToDest[startPin])
					{
						break;
					}
				}

				// Keep track of our starting pin
				byte cycleStartPin = startPin;

				// Adjacent pairs of pins are connected to a switcher which
				// may or may not swap them around.  Get the index for the
				// switcher we're attached to.
				byte switcher = (byte)(startPin / 2);

				// This is the pin we need to be mapped to
				byte endPin = permutationOuter[startPin];

				// Trace the cycle starting at startPin
				while (true)
				{
					// We alternate from input to output of the current permutation network
					fInput = !fInput;

					// Where we came from
					byte switcherPrev = switcher;
					switcher = (byte)(endPin / 2);

					// If we're connected to the wrong network currently...
					if ((endPin & 1) != network)
					{
						// If we're on the input side...);
						if (fInput)
						{
							// Swap the two input connections around
							inputMask = AddSwap(inputMask, switcher, delta, phase);
						}
						else
						{
							// Swap the two output connections around
							outputMask = AddSwap(outputMask, switcher, delta, phase);
						}
					}

					// Mark this input bit as mapped
					mappedToDest[fInput ? endPin : startPin] = true;

					// mark the connections that need to be made in the inner network
					permutationsInner[network][fInput ? switcher : switcherPrev] = fInput ? switcherPrev : switcher;

					// We've mapped one more pin
					cMapped++;

					// Get the other pin on this switcher
					startPin = (byte)(endPin ^ 1);

					// If we're back to startPin on the input side, then we've completed the cycle
					if (startPin == cycleStartPin && fInput)
					{
						break;
					}

					// The other pin on our switcher has to go to the other network
					network = (byte)(1 - network);

					// The pin we map to on the other side of the network
					endPin = fInput ? permutationOuter[startPin] : reversePermutation[startPin];
				}
			}
			return permutationsInner;
		}

		private static byte[] GetReversePermutation(byte[] permutation)
		{
			int size = permutation.Length;
			byte[] reversePermutation = new byte[size];
			for (byte i = 0; i < size; i++)
			{
				reversePermutation[permutation[i]] = i;
			}
			return reversePermutation;
		}

		private static ulong AddSwap(ulong maskCur, int switcher, int delta, int phase)
		{
			return maskCur | (1ul << (2 * switcher * delta + phase));
		}

		private void ExtractMasks(PermutationNetwork even, PermutationNetwork odd, ulong inputMask, ulong outputMask)
		{
			List<ulong> masksEven = even.Masks;
			List<ulong> masksOdd = odd.Masks;
			Masks.Add(inputMask);
			for (int i = 0; i < masksEven.Count; i++)
			{
				Masks.Add(masksEven[i] | masksOdd[i]);
			}
			Masks.Add(outputMask);
		}

		private static readonly int[] Deltas = new[] { 1, 2, 4, 8, 16, 32, 16, 8, 4, 2, 1 };

		public ulong Permute(ulong n)
		{
			for (int i = 0; i < Deltas.Length; i++)
			{
				ulong l = Masks[i];

				if (l != 0)
				{
					n = Bitops.SwapBitsMask(n, Deltas[i], l);
				}
			}
			return n;
		}
	}
}
