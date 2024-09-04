using Microsoft.AspNetCore.Authorization;
using Microsoft.AspNetCore.Mvc;
using Microsoft.EntityFrameworkCore;
using OrYaoSen_Proj.Data;
using OrYaoSen_Proj.Models;
using System.Linq;
using System.Security.Claims;
using System.Threading.Tasks;

namespace OrYaoSen_Proj.Controllers
{
    [Authorize]
    [Route("api/[controller]")]
    [ApiController]
    public class BookingsController : ControllerBase
    {
        private readonly ApplicationDbContext _context;

        public BookingsController(ApplicationDbContext context)
        {
            _context = context;
        }

        // GET: api/Bookings/GetAll
        [HttpGet]
        public IActionResult GetAll()
        {
            return Ok(_context.Bookings.ToList());
        }

        // GET: api/Bookings/ById/5
        [HttpGet("ById/{id}")]
        public IActionResult GetById(int? id)
        {
            var booking = _context.Bookings.FirstOrDefault(e => e.BookingId == id);
            if (booking == null)
            {
                return Problem(detail: "Booking with id " + id + " is not found.", statusCode: 404);
            }
            return Ok(booking);
        }

        // GET: api/Bookings/ByStatus/status
        [HttpGet("ByStatus/{status}")]
        public IActionResult GetByStatus(string status)
        {
            var bookings = _context.Bookings
                .Where(b => b.BookingStatus.ToLower() == status.ToLower())
                .ToList();
            if (!bookings.Any())
            {
                return Problem(detail: "No bookings with status " + status + " found.", statusCode: 404);
            }
            return Ok(bookings);
        }

        // GET: api/Bookings/Search
        [HttpGet("Search")]
        public IActionResult Search(
            [FromQuery] string? facilityDescription,
            [FromQuery] string? bookingDateFrom,
            [FromQuery] string? bookingDateTo,
            [FromQuery] string? bookedBy,
            [FromQuery] string? bookingStatus,
            [FromQuery] string? sortBy = "BookingDateFrom",
            [FromQuery] string? sortOrder = "ASC",
            [FromQuery] int pageNumber = 1,
            [FromQuery] int pageSize = 10)
        {
            var query = _context.Bookings.AsQueryable();

            if (!string.IsNullOrEmpty(facilityDescription))
            {
                query = query.Where(b => b.FacilityDescription.Contains(facilityDescription));
            }

            if (!string.IsNullOrEmpty(bookingDateFrom))
            {
                query = query.Where(b => b.BookingDateFrom == bookingDateFrom);
            }

            if (!string.IsNullOrEmpty(bookingDateTo))
            {
                query = query.Where(b => b.BookingDateTo == bookingDateTo);
            }

            if (!string.IsNullOrEmpty(bookedBy))
            {
                query = query.Where(b => b.BookedBy.Contains(bookedBy));
            }

            if (!string.IsNullOrEmpty(bookingStatus))
            {
                query = query.Where(b => b.BookingStatus.Contains(bookingStatus));
            }

            // Sorting
            query = sortBy switch
            {
                "FacilityDescription" => sortOrder.ToUpper() == "ASC" ? query.OrderBy(b => b.FacilityDescription) : query.OrderByDescending(b => b.FacilityDescription),
                "BookingDateFrom" => sortOrder.ToUpper() == "ASC" ? query.OrderBy(b => b.BookingDateFrom) : query.OrderByDescending(b => b.BookingDateFrom),
                "BookingStatus" => sortOrder.ToUpper() == "ASC" ? query.OrderBy(b => b.BookingStatus) : query.OrderByDescending(b => b.BookingStatus),
                "BookedBy" => sortOrder.ToUpper() == "ASC" ? query.OrderBy(b => b.BookedBy) : query.OrderByDescending(b => b.BookedBy),
                _ => query.OrderBy(b => b.BookingDateFrom)
            };

            var totalRecords = query.Count();
            var results = query.Skip((pageNumber - 1) * pageSize)
                               .Take(pageSize)
                               .ToList();

            if (!results.Any())
            {
                return Problem(detail: "No bookings found matching the provided criteria.", statusCode: 404);
            }

            return Ok(new
            {
                TotalRecords = totalRecords,
                PageNumber = pageNumber,
                PageSize = pageSize,
                Data = results
            });
        }

        // GET: api/Bookings/History
        [HttpGet("History")]
        public IActionResult GetBookingHistory(
            [FromQuery] string? bookedBy,
            [FromQuery] string? facilityDescription)
        {
            var query = _context.Bookings.AsQueryable();

            if (!string.IsNullOrEmpty(bookedBy))
            {
                query = query.Where(b => b.BookedBy == bookedBy);
            }

            if (!string.IsNullOrEmpty(facilityDescription))
            {
                query = query.Where(b => b.FacilityDescription == facilityDescription);
            }

            var results = query.OrderBy(b => b.BookingDateFrom).ToList();

            if (!results.Any())
            {
                return Problem(detail: "No booking history found.", statusCode: 404);
            }

            return Ok(results);
        }

        // POST: api/Bookings/Post
        [HttpPost]
        public IActionResult Post(Booking booking)
        {
            _context.Bookings.Add(booking);
            _context.SaveChanges();

            return CreatedAtAction("GetAll", new { id = booking.BookingId }, booking);
        }

        // PUT: api/Bookings/Put/5
        [HttpPut("{id}")]
        public IActionResult Put(int? id, Booking booking)
        {
            var entity = _context.Bookings.FirstOrDefault(b => b.BookingId == id);
            if (entity == null)
            {
                return Problem(detail: "Booking with id " + id + " is not found.", statusCode: 404);
            }

            entity.FacilityDescription = booking.FacilityDescription;
            entity.BookingDateFrom = booking.BookingDateFrom;
            entity.BookingDateTo = booking.BookingDateTo;
            entity.BookedBy = booking.BookedBy;
            entity.BookingStatus = booking.BookingStatus;

            _context.SaveChanges();

            return Ok(entity);
        }

        // DELETE: api/Bookings/Delete/5
        [HttpDelete("{id}")]
        public IActionResult Delete(int? id)
        {
            var entity = _context.Bookings.FirstOrDefault(b => b.BookingId == id);
            if (entity == null)
            {
                return Problem(detail: "Booking with id " + id + " is not found.", statusCode: 404);
            }

            _context.Bookings.Remove(entity);
            _context.SaveChanges();

            return Ok(entity);
        }

        // GET: api/Bookings/my-bookings
        [HttpGet("my-bookings")]
        public async Task<IActionResult> GetMyBookings()
        {
            var userName = User.FindFirstValue(ClaimTypes.Name);
            if (userName == null)
            {
                return Unauthorized(new { Status = "Error", Messege = "User not authenticated." });
            }

            var bookings = await _context.Bookings
                .Where(b => b.BookedBy == userName)
                .ToListAsync();
            
            return Ok(bookings);
        }
    }
}
